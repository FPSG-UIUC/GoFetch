#include "linked_list.h"
#include <stdlib.h>


linked_list_t* create_linked_list() {
    linked_list_t* linked_list = (linked_list_t*)malloc(sizeof(linked_list_t));
    linked_list->head = NULL;
    linked_list->tail = NULL;
    linked_list->num_nodes = 0;

    return linked_list;
}

void delete_linked_list(linked_list_t* linked_list) {
    free(linked_list);
}

void deep_delete_linked_list(linked_list_t* linked_list) {
    node_t* node_to_delete = linked_list->head;
    while (node_to_delete) {
        node_t* next_node_to_delete = node_to_delete->next;
        free(node_to_delete);
        node_to_delete = next_node_to_delete;
    }

    delete_linked_list(linked_list);
}

void add_preallocated_node_to_linked_list(linked_list_t *linked_list, node_t *new_node_addr) {

    // modify the old tail node
    if (linked_list->tail)
        linked_list->tail->next = new_node_addr;

    // modify the new node
    new_node_addr->next = 0;
    new_node_addr->last = linked_list->tail;

    // modify the linked list
    if ( __builtin_expect(linked_list->head == NULL, 0) ) {
        // add node to empty linked list
        linked_list->head = new_node_addr;
        linked_list->head->last = 0;
    }

    linked_list->tail = new_node_addr;
    linked_list->num_nodes++;
}


