from random import randrange
import numpy as np


"""
  Returns the rotation matrix of poly, i.e.,
  the matrix consisting of the coefficient vectors of
    poly, X * poly, X^2 * poly, ..., X^(deg(poly)-1) * poly
  modulo X^n-1.
  If cyclotomic = True, then reduction mod X^n+1 is applied, instead of X^n-1.
"""
def rotMatrix(poly, cyclotomic=False):
  n = len(poly)
  A = np.array( [[0]*n for _ in range(n)] )
  
  for i in range(n):
    for j in range(n):
      c = 1
      if cyclotomic and j < i:
        c = -1

      A[i][j] = c * poly[(j-i)%n]
      
  return A

"""
  Given a list of polynomials poly = [p_1, ...,p_n],
  this function returns an rows*cols matrix,
  consisting of the rotation matrices of p_1, ..., p_n.
"""
def module( polys, rows, cols ):
  if rows*cols != len(polys):
    raise ValueError("len(polys) has to equal rows*cols.")
  
  n = len(polys[0])
  for poly in polys:
    if len(poly) != n:
      raise ValueError("polys must not contain polynomials of varying degrees.")
  
  blocks = []
  
  for i in range(rows):
    row = []
    for j in range(cols):
      row.append( rotMatrix(polys[i*cols+j], cyclotomic=True) )
    blocks.append(row)
  
  return np.block( blocks )
