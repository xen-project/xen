/* bindings.c
 *
 * Manage subscriptions for the control interface switch.
 *
 * (c) 2004, Andrew Warfield
 *
 */

/* Interfaces:
 *
 * xcs_bind   (port, type, connection)
 *   - Register connection to receive messages of this type.
 * xcs_unbind (port, type, connection)
 *   - Remove an existing registration. (Must be an exact match)
 * xcs_lookup (port, type)
 *   - Return a list of connections matching a registration.
 * 
 * - All connections have a connection.bindings list of current bindings.
 * - (port, type) pairs may be wildcarded with -1.
 */
 
#include <stdio.h>
#include <stdlib.h> 
#include <errno.h>
#include <string.h>
#include "xcs.h"


typedef struct binding_ent_st {
    connection_t          *con;
    struct binding_ent_st *next;
} binding_ent_t;

#define BINDING_TABLE_SIZE       1024

static binding_ent_t *binding_table[BINDING_TABLE_SIZE];
        
#define PORT_WILD(_ent) ((_ent)->port == PORT_WILDCARD)
#define TYPE_WILD(_ent) ((_ent)->type == TYPE_WILDCARD)
#define FULLY_WILD(_ent) (PORT_WILD(_ent) && TYPE_WILD(_ent))

#define BINDING_HASH(_key) \
    ((((_key)->port * 11) ^ (_key)->type) % BINDING_TABLE_SIZE)
    
    
void init_bindings(void)
{
    memset(binding_table, 0, sizeof(binding_table));
}

static int table_add(binding_ent_t *table[],
                            connection_t *con, 
                            binding_key_t *key)
{
    binding_ent_t **curs, *ent;
        
    curs = &table[BINDING_HASH(key)];
    
    while (*curs != NULL) {
        if ((*curs)->con == con) {
            DPRINTF("Tried to add an ent that already existed.\n");
            goto done;
        }
        curs = &(*curs)->next;
    }
    
    if (connection_add_binding(con, key) != 0)
    {
       DPRINTF("couldn't add binding on connection (%lu)\n", con->id);
       goto fail;
    }
    ent = (binding_ent_t *)malloc(sizeof(binding_ent_t));
    if (ent == 0) {
       DPRINTF("couldn't alloc binding ent!\n");
       goto fail;
    }
    ent->con = con;
    ent->next = NULL;
    *curs = ent;
    
done:
    return 0;

fail:
    return -1;
}


static inline int binding_has_colliding_hashes(connection_t *con, 
                                               binding_key_t *key)
{
    int hash, count = 0;
    binding_key_ent_t *ent;
    
    ent = con->bindings; 
    hash = BINDING_HASH(key);
    
    while (ent != NULL) {
        if (BINDING_HASH(&ent->key) == hash) count ++;
        ent = ent->next;
    }
    
    return (count > 1);
}
static int table_remove(binding_ent_t *table[],
                            connection_t *con, 
                            binding_key_t *key)
{
    binding_ent_t **curs, *ent;
    
    if (!binding_has_colliding_hashes(con, key))
    {
    
        curs = &table[BINDING_HASH(key)];

        while ((*curs != NULL) && ((*curs)->con != con))
           curs = &(*curs)->next;

        if (*curs != NULL) {
           ent = *curs;
           *curs = (*curs)->next;
           free(ent);
        }
    }
    
    connection_remove_binding(con, key);
    
    return 0;    
}

int xcs_bind(connection_t *con, int port, u16 type)
{
    binding_key_t  key;
    
    key.port = port;
    key.type = type;
    
    return table_add(binding_table, con, &key);  
}

int xcs_unbind(connection_t *con, int port, u16 type)
{
    binding_key_t  key;
    
    key.port = port;
    key.type = type;
    
    return table_remove(binding_table, con, &key); 
}


static void for_each_binding(binding_ent_t *list, binding_key_t *key, 
                void (*f)(connection_t *, void *), void *arg)
{
    while (list != NULL) 
    {
        if (connection_has_binding(list->con, key))
            f(list->con, arg);
        list = list->next;
    }  
}

void xcs_lookup(int port, u16 type, void (*f)(connection_t *, void *), 
                void *arg)
{
    binding_key_t  key;
            
    key.port  = port; key.type = type;
    for_each_binding(binding_table[BINDING_HASH(&key)], &key, f, arg);
            
    key.port  = port; key.type = TYPE_WILDCARD;
    for_each_binding(binding_table[BINDING_HASH(&key)], &key, f, arg);
            
    key.port  = PORT_WILDCARD; key.type = type;
    for_each_binding(binding_table[BINDING_HASH(&key)], &key, f, arg);
            
    key.port  = PORT_WILDCARD; key.type = TYPE_WILDCARD;
    for_each_binding(binding_table[BINDING_HASH(&key)], &key, f, arg);
}
