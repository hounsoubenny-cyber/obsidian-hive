#ifndef DCHAINED_LIST_H
#define DCHAINED_LIST_H
#include <stdint.h>
#include "../flows/flow.h"

// File doublement chaînée INTRUSIVE : les liens (lru_prev, lru_next) sont dans la FlowEntry elle-même.
// head = le plus ancien, tail = le plus récent.
struct DChainedList{
    uint32_t max_element;         // 0 = infini
    uint32_t n_elements;
    FlowEntry *head;
    FlowEntry *tail;
};
typedef struct DChainedList DChainedList;

// Convention : 0 = succès, -1 = échec (NULL, ou liste pleine avec del = 0)
// del = 1 : si la liste est pleine, on supprime (et libère) l'élément à l'autre bout pour faire de la place
// delete_* : retire l'élément ET le libère avec free (une liste vide n'est pas une erreur : retourne 0)
DChainedList *create_dcl(uint32_t max_element);                 // NULL si échec
int add_to_end(DChainedList *dcl, FlowEntry *entry, int del);   // si plein et del = 1 : supprime le premier
int add_to_top(DChainedList *dcl, FlowEntry *entry, int del);   // si plein et del = 1 : supprime le dernier
int move_to_top(DChainedList *dcl, FlowEntry *entry);
int move_to_end(DChainedList *dcl, FlowEntry *entry);
int delete_from_end(DChainedList *dcl);
int delete_from_top(DChainedList *dcl);
int delete_entry(DChainedList *dcl, FlowEntry *entry);   // retire et libère CET élément (il doit être dans la liste)
#endif
