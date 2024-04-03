#ifndef __MATH_UTILS_H__
#define __MATH_UTILS_H__

void shuffle(void* array, int num_elements, int element_size);

void sort(void* array, int num_elements, int element_size);

int max(int a, int b);

int min(int a, int b);

float max_f(float* arr, int n);

float min_f(float* arr, int n);

float mean_f(float* arr, int n);

float median_f(float* arr, int n);

float std_f(float* arr, int n);

float q1_f(float* arr, int n);

float q3_f(float* arr, int n);

uint64_t max_8B(uint64_t* arr, int n);

uint64_t min_8B(uint64_t* arr, int n);

float mean_8B(uint64_t* arr, int n);

uint64_t median_8B(uint64_t* arr, int n);

float std_8B(uint64_t* arr, int n);

uint64_t q1_8B(uint64_t* arr, int n);

uint64_t q3_8B(uint64_t* arr, int n);

#endif
