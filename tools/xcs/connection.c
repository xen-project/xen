/*
 * connection.c
 *
 * State associated with a client connection to xcs.
 *
 * Copyright (c) 2004, Andrew Warfield
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xcs.h"

connection_t *connection_list = NULL;

#define CONNECTED(_c) (((_c)->ctrl_fd != -1) || ((_c)->data_fd != -1))

connection_t *get_con_by_session(unsigned long session_id)
{
    connection_t **c, *ent = NULL;
    
    c = &connection_list;
    
    DPRINTF("looking for id: %lu : %lu\n", session_id, (*c)->id);
    
    while (*c != NULL) 
    {
        if ((*c)->id == session_id) 
            return (*c);
        c = &(*c)->next;
    }
    
    return ent;
}

connection_t *connection_new()
{
    connection_t *con;
    
    con = (connection_t *)malloc(sizeof(connection_t));
    if (con == NULL)
    {
        DPRINTF("couldn't allocate a new connection\n");
        return NULL;
    }
    
    con->bindings = NULL;
    con->data_fd = -1;
    con->ctrl_fd = -1;
    
    /* connections need a unique session id. 
     * - this approach probably gets fixed later, but for the moment
     * is unique, and clearly identifies a connection.
     */
    con->id = (unsigned long)con;
    
    /* add it to the connection list */
    con->next = connection_list;
    connection_list = con;
    
    return (con);
}

void connection_free(connection_t *con)
{
    /* first free all subscribed bindings: */
    
    while (con->bindings != NULL)
        xcs_unbind(con, con->bindings->key.port, con->bindings->key.type);
    
    /* now free the connection. */
    free(con);
}
    
int connection_add_binding(connection_t *con, binding_key_t *key)
{
    binding_key_ent_t *key_ent;
    
    key_ent = (binding_key_ent_t *)malloc(sizeof(binding_key_ent_t));
    if (key_ent == NULL)
    {
        DPRINTF("couldn't alloc key in connection_add_binding\n");
        return -1;    
    }
    
    key_ent->key = *key;
    key_ent->next = con->bindings;
    con->bindings = key_ent;
    
    return 0;
}

int connection_remove_binding(connection_t *con, binding_key_t *key)
{
    binding_key_ent_t *key_ent;
    binding_key_ent_t **curs = &con->bindings;
    
    while ((*curs != NULL) && (!BINDING_KEYS_EQUAL(&(*curs)->key, key)))
        curs = &(*curs)->next;
    
    if (*curs != NULL) {
        key_ent = *curs;
        *curs = (*curs)->next;
        free(key_ent);
    }
    
    return 0;   
}


int connection_has_binding(connection_t *con, binding_key_t *key)
{
    binding_key_ent_t *ent;
    int ret = 0;
    
    ent = con->bindings;
    
    while (ent != NULL) 
    {
        if (BINDING_KEYS_EQUAL(key, &ent->key))
        {
            ret = 1;
            break;
        }
        ent = ent->next;
    }
    
    return ret;
}


void gc_connection_list(void)
{
    connection_t **c, *ent = NULL;
    struct timeval now, delta;

    c = &connection_list;
    gettimeofday(&now, NULL);

    while ( *c != NULL )
    {
        if ( !CONNECTED(*c) )
        {
            timersub(&now, &(*c)->disconnect_time, &delta);
            if ( delta.tv_sec >= XCS_SESSION_TIMEOUT )
            {
                DPRINTF("        : Freeing connection %lu after %lds\n", 
                     (*c)->id, delta.tv_sec);
                ent = *c;
                *c = (*c)->next;
                connection_free(ent);
                continue;
            }
        }
        c = &(*c)->next;
    }
}
