#ifndef __LINKED_LIST_H__
#define __LINKED_LIST_H__

#include <stdint.h>
#include <stdlib.h>

// one node is 8B + 8B = 16B = 0x10B
typedef struct node_t {
    struct node_t* next;
    struct node_t* last;
} node_t;

typedef struct {
    node_t* head;
    node_t* tail;
    int num_nodes;
} linked_list_t;

linked_list_t* create_linked_list();

// only delete the linked list. don't actually delete the nodes
void delete_linked_list(linked_list_t* linked_list);

// delete the nodes and the linked list.
// this method shouldn't be used in the eviction set creation
void deep_delete_linked_list(linked_list_t* linked_list);

void add_preallocated_node_to_linked_list(linked_list_t* linked_list, node_t* new_node_addr);

#endif
