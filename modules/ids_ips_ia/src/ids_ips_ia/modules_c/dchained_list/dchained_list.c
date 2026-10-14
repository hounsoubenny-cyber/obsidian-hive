#include "dchained_list.h"
#include <stdlib.h>
#include <string.h>

static void _fill_empty_dcl(DChainedList *dcl, FlowEntry *entry){
    dcl -> head = entry;
    dcl -> tail = entry;
    entry -> lru_next = NULL;
    entry -> lru_prev = NULL;
    dcl -> n_elements += 1;
}

static void _add_to_end(DChainedList *dcl, FlowEntry *entry){
    if (dcl -> n_elements == 0){
        _fill_empty_dcl(dcl, entry);
        return;
    }
    entry -> lru_next = NULL;
    entry -> lru_prev = dcl -> tail;
    dcl -> tail -> lru_next = entry;
    dcl -> tail  = entry;
    entry -> dcl_pos = dcl -> n_elements - 1;
    dcl -> n_elements += 1;
}

static void _add_to_top(DChainedList *dcl, FlowEntry *entry){
    if (dcl -> n_elements == 0){
        _fill_empty_dcl(dcl, entry);
        return;
    }
    entry -> lru_prev = NULL;
    entry -> lru_next = dcl -> head;
    dcl -> head -> lru_prev = entry;
    dcl -> head = entry;
    entry -> dcl_pos = dcl -> n_elements - 1;
    dcl -> n_elements += 1;
}

DChainedList *create_dcl(uint32_t max_element){
    DChainedList *dcl = (DChainedList *)calloc(1, sizeof(DChainedList));   // calloc : head, tail, n_elements à 0
    if (dcl == NULL) return NULL;
    dcl -> max_element = max_element;
    return dcl;
}

int add_to_end(DChainedList *dcl, FlowEntry *entry, int del){
    if (dcl == NULL || entry == NULL) return -1;
    if (dcl -> n_elements == 0){
        _fill_empty_dcl(dcl, entry);
        return 0;
    }
    if (dcl -> max_element == 0){
        _add_to_end(dcl, entry);
        return 0;
    }
    if (dcl -> max_element < dcl -> n_elements + 1){
        if (del == 0) return -1;
        if (delete_from_top(dcl) == 0){
            _add_to_end(dcl, entry);
            return 0;
        }
        return -1;
    }
    _add_to_end(dcl, entry); 
    return 0;
}

int add_to_top(DChainedList *dcl, FlowEntry *entry, int del){
    if (dcl == NULL || entry == NULL) return -1;
    if (dcl -> n_elements == 0){
        _fill_empty_dcl(dcl, entry);
        return 0;
    }
    if (dcl -> max_element == 0){
        _add_to_top(dcl, entry);
        return 0;
    }
    if (dcl -> max_element < dcl -> n_elements + 1){
        if (del == 0) return -1;
        if (delete_from_end(dcl) == 0){
            _add_to_top(dcl, entry);
            return 0;
        }
        return -1;
    }
    _add_to_top(dcl, entry); 
    return 0;
}

int move_to_top(DChainedList *dcl, FlowEntry *entry){
    if (dcl == NULL || entry == NULL) return -1;
    FlowEntry *head = dcl -> head;
    FlowEntry *tail = dcl -> tail;
    if (entry == head) return 0;
    if (tail == entry){ // Cas mettre le dernier au début
        FlowEntry *tail_prev = tail -> lru_prev;
        tail_prev -> lru_next = NULL;  // Mettre son suivant a null
        tail -> lru_prev = NULL;      // Mettre son precedent a null
        tail -> lru_next = head;      // Le suivant de tail devient head
        head -> lru_prev = tail;     // Le précedent de head devient tail
        dcl -> head = tail;             // le tail devient tail_prev
        dcl -> tail = tail_prev;           // le head devient tail
        return 0;
    }
    // Sinon
    FlowEntry *prev = entry -> lru_prev;
    FlowEntry *next = entry -> lru_next;
    prev -> lru_next = next;       // son precedent a pour suivant le suivant et verça
    next -> lru_prev = prev;
    entry -> lru_next = head;  // le next de entry est head
    entry -> lru_prev = NULL;   // Son précedent devient null
    head -> lru_prev = entry;
    dcl -> head = entry;      // head devient entry
    return 0;
}

int move_to_end(DChainedList *dcl, FlowEntry *entry){
    if (dcl == NULL || entry == NULL) return -1;
    FlowEntry *head = dcl -> head;
    FlowEntry *tail = dcl -> tail;
    if (entry == tail) return 0;
    if (head == entry){ // Cas mettre le début en fin
        FlowEntry *head_next = head -> lru_next;
        head_next -> lru_prev = NULL; //Mettre le précedent a null
        head -> lru_next = NULL;     // mettre non suivant a null
        tail -> lru_next = head;     // suivant de tail est next
        head -> lru_prev = tail;     // sonc precedent est tail
        dcl -> head = head_next;    // head devient head next
        dcl -> tail = head;         // tail devient head
        return 0;
    }
    // Sinon
    FlowEntry *prev = entry -> lru_prev;
    FlowEntry *next = entry -> lru_next;
    prev -> lru_next = next;       // son precedent a pour suivant le suivant et verça
    next -> lru_prev = prev;
    entry -> lru_next = NULL;  // le next de entry est NUll
    entry -> lru_prev = tail;  // son prev est tail
    tail -> lru_next = entry;
    dcl -> tail = entry;      // tail devient entry
    return 0;
}

int delete_from_end(DChainedList *dcl){
    if (dcl == NULL) return -1;
    if (dcl -> n_elements == 0) return 0;   // liste vide : rien à supprimer, pas une erreur
    FlowEntry *tmp = dcl -> tail;
    if (dcl -> n_elements == 1){
        dcl -> head = NULL;
        dcl -> tail = NULL;
    }else{
        dcl -> tail = dcl -> tail -> lru_prev;
        dcl -> tail -> lru_next = NULL;
    }
    free(tmp);
    dcl -> n_elements -= 1;
    return 0;
}

int delete_from_top(DChainedList *dcl){
    if (dcl == NULL) return -1;
    if (dcl -> n_elements == 0) return 0;   // liste vide : rien à supprimer, pas une erreur
    FlowEntry *tmp = dcl -> head;
    if (dcl -> n_elements == 1){
        dcl -> head = NULL;
        dcl -> tail = NULL;
    }
    else{
        dcl -> head = dcl -> head -> lru_next;
        dcl -> head -> lru_prev = NULL;
    }
    free(tmp);
    dcl -> n_elements -= 1;
    return 0;
}

int delete_entry(DChainedList *dcl, FlowEntry *entry){
    if (dcl == NULL || entry == NULL) return -1;
    if (entry == dcl -> head) return delete_from_top(dcl);   // les bouts ont déjà leur fonction
    if (entry == dcl -> tail) return delete_from_end(dcl);
    entry -> lru_prev -> lru_next = entry -> lru_next;       // au milieu : le précédent et le suivant se donnent la main
    entry -> lru_next -> lru_prev = entry -> lru_prev;
    free(entry);
    dcl -> n_elements -= 1;
    return 0;
}
