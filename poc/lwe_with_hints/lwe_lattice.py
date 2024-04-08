from fpylll import BKZ as BKZ_FPYLLL, LLL, GSO, IntegerMatrix, FPLLL
from fpylll.algorithms.bkz2 import BKZReduction

import numpy as np
from math import sqrt, pi, e, log, ceil

import time
from copy import deepcopy
import warnings

FPLLL.set_precision(120)

class LWELattice:
  
  """
    Constructor, that builds an LWE lattice.
    Params:
      A,b,q: LWE instance. A and b have to be numpy arrays.
      verbose: If True, then runs in verbose mode (optional).
  """
  def __init__(
    self,
    A,b,q,
    verbose = False
  ):
  
    
    self.__A = A
    self.__b = b
    self.__q = q
    
    self.__n, self.__m = A.shape
    
    self.__perfectHints = []
    self.__modHints = []
    self.__approximateHints = []
    
    self.basis = None
    self.successBlocksize = 0
    self.s = None
    self.shortestVector = None
    
    #Speed-up, when given mod-q hints only
    self.__modQHintsOnly = True
    self.__modQTransformationMatrix = None
    self.__modQEliminatedCoordinates = None
    
    #Verbose mode
    self.__verbose = verbose
    self.__clockTicking = False
    self.__time = 0
    
  """
    Integrates perfect hint.
    Params:
      v: Hint vector, has to be a numpy array.
      l: Hint value.
  """
  def integratePerfectHint(self, v, l ):
    self.__checkHintFormat(v)
    
    if len(self.__perfectHints) < self.__n:
      self.__perfectHints.append( np.append(v,l) )
      self.__modQHintsOnly = False
    else:
      raise ValueError("Can't integrate more than n perfect hints.")
  
  """
    Integrates modular hint.
    Params:
      v: Hint vector, has to be a numpy array.
      l: Hint value.
      m: Hint modulus.
  """
  def integrateModularHint(self, v, l, m ):
    self.__checkHintFormat(v)
    self.__modHints.append( [m, np.append(v,l)] )
    
    if m != self.__q:
      self.__modQHintsOnly = False
    
  """
    Integrates approximate hint.
    This feature of our algorithm is not documented in our paper,
    because it is inferior to DDGR's approach for integrating approximate hints.
    Params:
      v: Hint vector, has to be a numpy array.
      l: Hint value.
  """
  def integrateApproximateHint( self, v, l ):
    self.__checkHintFormat(v)
    if len(self.__approximateHints) < self.__n:
      self.__approximateHints.append( np.append(v,l) )
      self.__modQHintsOnly = False
    else:
      raise ValueError("Can't integrate more than n approximate hints.")
  
  """
    Run Progressive-BKZ on the lattice with integrated hints.
    Params:
      terminateAtGH: If True, then terminate as soon as vector of norm < gaussian heuristic is found.
      targetLength: Terminate, when vector of norm < targetLength is found (optional). If set, terminateAtGH will be ignored.
      maxBlocksize: Terminate at maxBlocksize (optional). terminateAtGH / targetLength won't be ignored.
      bkzTours: BKZ tours per blocksize (optional).
  """
  def reduce(self, terminateAtGH = True, targetLength = None, maxBlocksize = None, bkzTours = 8 ):
    self.__vPrint("Constructing basis.")
    self.__clock()
    basis = self.__constructBasis()
    self.__clock()
    self.__vPrint("Finished basis construction. Time: %fs." % self.__time)
    
    noKannanEmbedding = ( np.array(basis[-1])[:-1] == 0 ).all()
    
    if noKannanEmbedding:
      basis = basis.submatrix(0,0,self.__m+self.__n,self.__m+self.__n)
      
    else:
      self.__vPrint("Constructing sublattice.")
      self.__clock()
      basis = self.__constructSubLattice(basis)
      self.__clock()
      self.__vPrint("Finished sublattice construction. Time: %fs." % self.__time)
    
    if maxBlocksize == None:
      maxBlocksize = basis.nrows

    if terminateAtGH and targetLength == None:
      targetLength = sqrt( basis.ncols / ( 2*pi*e ) * self.__q )
    
    foundSecret = False
    
    i = 0
    while not foundSecret and i < basis.nrows:
      candidate = basis[i]
      foundSecret = self.__checkCandidateShortest(candidate, targetLength)
      i += 1
    
    if foundSecret:
      self.__vPrint("Found secret while constructing sublattice.")
      self.shortestVector = np.array(basis[i-1])
      
    else:
      M = GSO.Mat( basis, float_type="mpfr" )
      M.update_gso()
      bkz = BKZReduction(M)

      self.__vPrint("Starting LLL.")
      self.__clock()
      bkz.lll_obj()
      self.__clock()
      self.__vPrint("Finished LLL. Time: %fs." % self.__time)

      beta = 2

      
      while not foundSecret and beta < maxBlocksize + 1:
        
        self.__vPrint("Starting BKZ with blocksize %d." % beta)
        
        par = BKZ_FPYLLL.Param(
          beta,
          strategies=BKZ_FPYLLL.DEFAULT_STRATEGY,
          max_loops=8,
          flags=BKZ_FPYLLL.MAX_LOOPS
        )

        self.__clock()

        for tour in range(bkzTours):
          bkz(par)

          foundSecret = self.__checkCandidateShortest(basis[0], targetLength)

          if foundSecret:
            self.successBlocksize = beta

            self.__vPrint("Found secret at blocksize %d." % beta)

            break

        self.__clock()

        self.__vPrint("Finished BKZ with blocksize %d. Time: %fs." % (beta, self.__time))

        beta += 1
        
      self.shortestVector = np.array(basis[0])
    
    if noKannanEmbedding:
      self.s = self.shortestVector[self.__m:]
    else:
      self.s = self.__recoverRemainingCoordinates()
    
  def __checkCandidateShortest(self, candidate, targetLength):
    if targetLength is not None:
      return candidate.norm() < targetLength
    else:
      return False
  
  def __constructBasis(self):
        
    if not self.__modQHintsOnly:
      A = self.__A
      b = self.__b
      
      m = self.__m
      n = self.__n
    
      ctrModHints = len(self.__modHints)
      ctrPerfectHints = len(self.__perfectHints)
      ctrApproximateHints = len(self.__approximateHints)
      
    else:
      self.__vPrint("Only mod-q hints have been integrated. Going to smaller LWE dimension.")
      A,b = self.__modQOnlyDimRed()
      
      n,m = A.shape
      
      ctrModHints = 0
      ctrPerfectHints = 0
      ctrApproximateHints = 0
      
    dim = m + ctrModHints + n + 1
    
    B = IntegerMatrix.identity(dim)
    
    #q-block
    for i in range(m):
      B[i,i] = self.__q
    
    #A
    for i in range(n):
      for j in range(m):
        B[i+m+ctrModHints,j] = int(A[i][j])
    
    #Modular hints
    for i in range(ctrModHints):
      for j in range(n+2):
          if j<=n:
            B[j+m+ctrModHints,i+m] = int(self.__modHints[i][1][j])
          else:
            B[i+m,i+m] =  self.__modHints[i][0]
          
    #Perfect hints
    for i in range(ctrPerfectHints):
      for j in range(n+1):
          B[j+m+ctrModHints,i+m+ctrModHints] = int(self.__perfectHints[i][j])
              
    #Approximate hints
    for i in range(ctrApproximateHints):
      for j in range(n+1):
          if i + ctrPerfectHints < n:
            B[j+m+ctrModHints,i+m+ctrModHints+ctrPerfectHints] = int(self.__approximateHints[i][j])
          else:
            warnings.warn("Ignoring approximate hint, since there are already enough many perfect hints.", RuntimeWarning)
      
    #b  
    for i in range(m):
      B[m+ctrModHints+n,i] = int(b[i])
    
    return B
    
  def __constructSubLattice(self,basis):
    ctrModHints = len(self.__modHints)
    ctrPerfectHints = len(self.__perfectHints)
    ctrHints = ctrModHints + ctrPerfectHints
    
    if ctrHints == 0 or self.__modQHintsOnly:
      return basis
      
    else:
      m = self.__m
      n = self.__n
      q = self.__q
      
      #Split basis as
      #  [
      #    top
      #    bottom_left | bottom_right
      #  ].
      top = basis[:m]
      bottom = basis[m:]
      bottom_left = bottom.submatrix(0,0,n+ctrModHints+1,m)
      bottom_right = bottom.submatrix(0,m,n+ctrModHints+1,m+ctrModHints+n+1)
    
      dim_bottom = bottom.nrows
    
      #Scale bottom_right for zero forcing
      gh = self.__gaussianHeuristic(bottom_right)
      scaling = ceil( (2)**((dim_bottom-1)/2) * gh )
      
      for i in range(dim_bottom):
        for j in range(ctrHints):
          bottom_right[i,j] *= scaling
          
      #LLL reduce bottom_right
      U = IntegerMatrix.identity(dim_bottom)
      LLL.reduction(bottom_right, U)
        
      #Check if heuristics hold
      zero_block = bottom_right.submatrix(0,0,dim_bottom-ctrHints,ctrHints)
      for v in zero_block:
        if not v.is_zero():
          raise RuntimeError("Heuristics for Construct-Sublattice failed.")
    
      #Construct new basis
      bottom_left = U * bottom_left
      bottom_left = bottom_left[:-ctrHints]
      bottom_left = bottom_left % q
    
      dim_bottom = bottom_left.nrows
    
      B = IntegerMatrix.identity(m+dim_bottom)
    
      for i in range(m):
        B[i,i] = q
    
      for i in range(dim_bottom):
        for j in range(m):
          B[m+i,j] = bottom_left[i,j]
        for j in range(dim_bottom):
          B[m+i,m+j] = bottom_right[i,j+ctrHints]
      
      return B
  
  def __recoverRemainingCoordinates(self):
    sV = self.shortestVector
    m = self.__m
    n = self.__n
    q = self.__q
    ctrPerfectHints = len(self.__perfectHints)
    ctrModHints = len(self.__modHints)
    ctrApproximateHints = len(self.__approximateHints)
    
    if sV[-1]==1:
      sV *= -1
    
    if self.__modQHintsOnly:
      s_1 = sV[m:]
      s_2 = (-s_1.dot(self.__modQTransformationMatrix)) % q
      
      s = np.zeros(n, dtype=int)
      
      ctrS1 = 0
      ctrS2 = 0
      
      for i in range(n):
        if i in self.__modQEliminatedCoordinates:
          s[i] = s_2[ctrS2]
          ctrS2 += 1
        else:
          s[i] = s_1[ctrS1]
          ctrS1 += 1
      
    else:
      #Collect all available v, l, such that s*v = l,
      #and then construct linear system of equations  s*M = y.
  
      cols = m+n+ctrModHints
      M = np.zeros( (n, cols), dtype=int )
      y = np.array( [0]*cols, dtype=int )
  
      for i in range( cols ):
    
        #LWE samples
        if i < m:
          v = self.__A[:,i]
          l = self.__b[i] + sV[i]
    
        #Approximate hints
        elif i < m + ctrApproximateHints and i < m + n -ctrPerfectHints:
          v,l = self.__splitHint( self.__approximateHints[i-m] )
          l += sV[i]
          l %= q
    
        #Coordinates recovered by lattice reduction
        elif i < m + n - ctrPerfectHints:
          v = np.zeros(n,dtype=int)
          v[i-m+ctrPerfectHints] = 1
          l = sV[i]
    
        #Perfect hints
        elif i < m + n:
          v,l = self.__splitHint( self.__perfectHints[i+ctrPerfectHints-m-n] )
          l %= q
    
        #Mod-q hints
        else:
          m_, v_ = self.__modHints[i-m-n]
          if m_ == q:
            v,l = self.__splitHint( v_ )
          else:
            v = np.zeros(n, dtype=int)
            l = 0
    
        M[:,i] = v
        y[i] = l
    
      #Solve via Gaussian elimination
      M,y = self.__gaussianElimination(M,y,n,q)
      
      s = np.array( [ y[i] for i in range(n) ] )
      
        
    for i in range(n):
      if s[i] > q/2:
        s[i] -= q
      
    return s
  
  def __modQOnlyDimRed(self):
    n = self.__n
    m = self.__m
    k = len(self.__modHints)
    
    cols = k+m
    
    M = np.zeros( (n,cols), dtype=int )
    y = np.array( [0]*cols )
    
    for i in range(k):
      v,l = self.__splitHint( self.__modHints[i][1] )
      M[:,i] = v
      y[i] = l
    
    for i in range(m):
      M[:,k+i] = self.__A[:,i]
      y[k+i] = self.__b[i]
    
    M,y = self.__gaussianElimination(M,y,k,self.__q,k)
    
    eliminatedCoordinates = []
    
    i = 0
    
    while i < n and len(eliminatedCoordinates) < k:
      
      isEliminated = True
      
      j = 0
      
      while isEliminated and j < cols:
        if j==len(eliminatedCoordinates):
          if  M[i,j] != 1:
            isEliminated = False
        elif M[i,j] != 0:
          isEliminated = False

        j += 1
        
      if isEliminated:
        eliminatedCoordinates.append( i )
      
      i += 1
    
    transformationMatrix = [ M[i,0:k] for i in range(n) if i not in eliminatedCoordinates ]
    transformationMatrix.append( y[0:k] )
    transformationMatrix = np.array(transformationMatrix)
    A = [ M[i,k:] for i in range(n) if i not in eliminatedCoordinates ]
    A = np.array(A)
    b = y[k:]
    
    self.__modQEliminatedCoordinates = eliminatedCoordinates
    self.__modQTransformationMatrix = transformationMatrix
    
    return A,b
    
  
  def __checkHintFormat(self, v):
    if len(v) != self.__n:
      raise ValueError("Expected hint of dimension %d, but got %d." % (self.__n, len(v)))
    
  def __splitHint(self, v_):
    v = v_[:-1]
    l = v_[-1]
    return (v,l)
   
  def __gaussianHeuristic(self, basis):
    dim = basis.nrows
    
    M = GSO.Mat(basis)
    M.update_gso()
    
    root_det = M.get_root_det(0,-1) #Appears to be buggy. May result in NaN.
    
    if np.isnan(root_det):
      self.__vPrint("fpylll failed to compute root_det. Resort to approximation via Hadamard bound.")
      
      #Approximate root_det by Hadamard bound.
      log_root_hadamard = 0
      for v in basis:
        log_root_hadamard += log(v.norm()) / dim
      log_root_hadamard = ceil(log_root_hadamard)
      root_det = e**log_root_hadamard
    
    gh = sqrt( dim / (2*pi*e) ) * root_det
    
    return gh
  
  """
      Extended Euclidean Algorithm
  """
  def __egcd(self,a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = self.__egcd(b % a, a)
        return (g, x - (b // a) * y, y)
        
  """
    Run Gaussian elimination over Z_q on a linear system of equations
        x*M = y
    to eliminate k coordinates of x.
    If the optional parameter restrictColumns is set,
    then the algorithm uses only the first restrictColumns columns
    to eliminate coordinates.
    
    Returns M', y', such that
        x * M' = y',
    where k rows of M' are eliminated.
  """
  def __gaussianElimination(self,M,y,k,q,restrictColumns = None):
    rows, cols = M.shape
    
    if k > rows:
      raise IndexError("Value of k has to be <= than dimension of unknown. Got k=%d, but was expecting k<%d" % (k,rows))
    
    if restrictColumns == None:
      restrictColumns = cols
    
    M_ = np.zeros( (rows+1,cols), dtype=int )
    for i in range(rows):
      for j in range(cols):
        M_[i,j] = M[i,j]
    
    for j in range(cols):
      M_[rows,j] = y[j]
    
    rowCtr = 0
    eliminatedCoordinates = 0

    while rowCtr < rows and eliminatedCoordinates < k:
    
        colCtr = eliminatedCoordinates
        foundInvertible = False
        while colCtr < restrictColumns and not foundInvertible:
            g,s,t = self.__egcd(M_[rowCtr,colCtr], q)
            if g==1:
                foundInvertible = True
            else:
                colCtr += 1
    
        if foundInvertible:
        
            M_[:,colCtr] *= s
            M_[:,colCtr] %= q
        
            if colCtr != eliminatedCoordinates:
                M_[:,[eliminatedCoordinates,colCtr]] = M_[:,[colCtr,eliminatedCoordinates]]
        
            for colCtr in range(cols):
                if colCtr != eliminatedCoordinates:
                    M_[:,colCtr] -= M_[rowCtr,colCtr]*M_[:,eliminatedCoordinates]
                    M_[:,colCtr] %= q
        
            eliminatedCoordinates += 1
    
        rowCtr += 1

    if eliminatedCoordinates < k:
        #Arises when columns are not linearly independent.
        raise RuntimeError("Gaussian elimination failed. Could only eliminate %d coordinates, instead of %d." % (eliminatedCoordinates,k))
    
    return M_[:-1], M_[-1]
  
  def __clock(self):
    if self.__clockTicking:
      self.__time = time.time() - self.__time
      self.__clockTicking = False
    else:
      self.__time = time.time()
      self.__clockTicking = True
  
  def __vPrint(self, s):
    if self.__verbose:
      print(str(s))
    