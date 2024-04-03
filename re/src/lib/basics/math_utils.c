#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

#include "math_utils.h"


void shuffle_8B(uint64_t* array, int num_elements) {
    if (num_elements < 2)
        return;
    for (int i = 0; i < num_elements-1; i++) {
        int j = i + rand() / (RAND_MAX / (num_elements - i) + 1);
        // swap array[i] and array[j]
        uint64_t tmp = array[j];
        array[j] = array[i];
        array[i] = tmp;
    }
}

void shuffle(void* array, int num_elements, int element_size) {
    if (element_size == 8)
        shuffle_8B((uint64_t*)array, num_elements);
    else {
        printf("ERROR: haven't implemented shuffle() for %d byte\n", element_size);
        exit(1);
    }
}

// Merges arr[left_idx...mid_idx] and arr[mid_idx+1..right_idx]
void merge_8B(uint64_t* array, int left_idx, int mid_idx, int right_idx) {
    int i, j, k;
    int n1 = mid_idx - left_idx + 1;
    int n2 = right_idx - mid_idx;

    /* create temp arrays */
    uint64_t L[n1], R[n2];

    /* Copy data to temp arrays L[] and R[] */
    for (i = 0; i < n1; i++)
        L[i] = array[left_idx + i];
    for (j = 0; j < n2; j++)
        R[j] = array[mid_idx + 1 + j];

    /* Merge the temp arrays back into arr[l..r]*/
    i = 0; // Initial index of first subarray
    j = 0; // Initial index of second subarray
    k = left_idx; // Initial index of merged subarray
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            array[k] = L[i];
            i++;
        }
        else {
            array[k] = R[j];
            j++;
        }
        k++;
    }

    /* Copy the remaining elements of L[], if there are any */
    while (i < n1) {
        array[k] = L[i];
        i++;
        k++;
    }

    /* Copy the remaining elements of R[], if there are any */
    while (j < n2) {
        array[k] = R[j];
        j++;
        k++;
    }
}

void merge_4B(uint32_t* array, int left_idx, int mid_idx, int right_idx) {
    int i, j, k;
    int n1 = mid_idx - left_idx + 1;
    int n2 = right_idx - mid_idx;

    /* create temp arrays */
    uint32_t L[n1], R[n2];

    /* Copy data to temp arrays L[] and R[] */
    for (i = 0; i < n1; i++)
        L[i] = array[left_idx + i];
    for (j = 0; j < n2; j++)
        R[j] = array[mid_idx + 1 + j];

    /* Merge the temp arrays back into arr[l..r]*/
    i = 0; // Initial index of first subarray
    j = 0; // Initial index of second subarray
    k = left_idx; // Initial index of merged subarray
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            array[k] = L[i];
            i++;
        }
        else {
            array[k] = R[j];
            j++;
        }
        k++;
    }

    /* Copy the remaining elements of L[], if there are any */
    while (i < n1) {
        array[k] = L[i];
        i++;
        k++;
    }

    /* Copy the remaining elements of R[], if there are any */
    while (j < n2) {
        array[k] = R[j];
        j++;
        k++;
    }
}

void merge_sort_8B(uint64_t* array, int left_idx, int right_idx)
{
    if (left_idx < right_idx) {
        // Same as (l+r)/2, but avoids overflow for large l and h
        int mid_idx = left_idx + (right_idx - left_idx) / 2;

        // Sort first and second halves
        merge_sort_8B(array, left_idx, mid_idx);
        merge_sort_8B(array, mid_idx + 1, right_idx);

        merge_8B(array, left_idx, mid_idx, right_idx);
    }
}

void merge_sort_4B(uint32_t* array, int left_idx, int right_idx)
{
    if (left_idx < right_idx) {
        // Same as (l+r)/2, but avoids overflow for large l and h
        int mid_idx = left_idx + (right_idx - left_idx) / 2;

        // Sort first and second halves
        merge_sort_4B(array, left_idx, mid_idx);
        merge_sort_4B(array, mid_idx+1, right_idx);

        merge_4B(array, left_idx, mid_idx, right_idx);
    }
}

void sort(void* array, int num_elements, int element_size) {
    if (element_size == 8)
        merge_sort_8B((uint64_t*)array, 0, num_elements-1);
    else if (element_size == 4)
        merge_sort_4B((uint32_t*)array, 0, num_elements-1);
    else {
        printf("ERROR: haven't implemented shuffle() for %d byte\n", element_size);
        exit(1);
    }
}

int max(int a, int b) {
    return (a > b) ? a : b;
}

int min(int a, int b) {
    return (a > b) ? b : a;
}

float max_f(float* arr, int n) {
    sort(arr, n, sizeof(float));
    return arr[n-1];
}

float min_f(float* arr, int n) {
    sort(arr, n, sizeof(float));
    return arr[0];
}

float mean_f(float* arr, int n) {
    float sum = 0.0;
    for (int i = 0; i < n; i++)
        sum += arr[i];
    return sum / n;
}

float median_f(float* arr, int n) {
    sort(arr, n, sizeof(float));
    return arr[n/2];
}

float std_f(float* arr, int n) {
    float mean = mean_f(arr, n);
    float variance = 0.0;
    for (int i = 0; i < n; i++)
        variance += (arr[i] - mean) * (arr[i] - mean);

    variance = variance / n;

    float std = sqrtf(variance);

    return std;
}

float q1_f(float* arr, int n) {
    sort(arr, n, sizeof(float));
    return arr[n/4];
}

float q3_f(float* arr, int n) {
    sort(arr, n, sizeof(float));
    return arr[n*3/4];
}

uint64_t max_8B(uint64_t* arr, int n) {
    sort(arr, n, sizeof(uint64_t));
    return arr[n-1];
}

uint64_t min_8B(uint64_t* arr, int n) {
    sort(arr, n, sizeof(uint64_t));
    return arr[0];
}

float mean_8B(uint64_t* arr, int n) {
    float sum = 0.0;
    for (int i = 0; i < n; i++)
        sum += (float)arr[i];
    return sum / n;
}

uint64_t median_8B(uint64_t* arr, int n) {
    sort(arr, n, sizeof(uint64_t));
    return arr[n/2];
}

float std_8B(uint64_t* arr, int n) {
    float mean = mean_8B(arr, n);
    float variance = 0.0;
    for (int i = 0; i < n; i++)
        variance += ((float)arr[i] - mean) * ((float)arr[i] - mean);

    variance = variance / n;

    float std = sqrtf(variance);

    return std;
}

uint64_t q1_8B(uint64_t* arr, int n) {
    sort(arr, n, sizeof(uint64_t));
    return arr[n/4];
}

uint64_t q3_8B(uint64_t* arr, int n) {
    sort(arr, n, sizeof(uint64_t));
    return arr[n*3/4];
}
