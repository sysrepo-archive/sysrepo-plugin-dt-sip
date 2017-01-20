#include <libubox/list.h>
#include "sysrepo.h"
#include "sysrepo/plugins.h"

struct ring {
    struct list_head head;
    char *ring;
};

void
free_rings(struct ring *rings)
{
    struct ring *r;
    list_for_each_entry(r, &rings->head, head) {
        free(r->ring);
        list_del(&r->head);
    }
}

void
print_rings(struct ring *rings)
{
    struct ring *r;
    list_for_each_entry(r, &rings->head, head) {
        printf("\tring: %s\n", r->ring);
    }
}


struct extension {
    struct list_head head;

    char *name;
    char *type;
    char *context;
    char *target;
    char *external;
    char *international;
    char *trunk;
    struct ring *rings;
    char *codecs;
    char *server;
};

void
print_extension(struct extension *ext)
{
    printf("extension:\n");
    printf("\tname: %s\n\ttype: %s\n\tcontext %s\n\ttarget %s\n\texternal %s\n\tinternational %s\n\ttrunk %s\n\tcodecs %s\n\tserver %s\n",
           ext->name,
           ext->type,
           ext->context,
           ext->target,
           ext->external,
           ext->international,
           ext->trunk,
           ext->codecs,
           ext->server);
    print_rings(ext->rings);
}

void
free_extension(struct extension *ext)
{
    free(ext->name);
    free(ext->type);
    free(ext->context);
    free(ext->target);
    free(ext->external);
    free(ext->international);
    free(ext->trunk);
    free_rings(ext->rings);
    free(ext->codecs);
    free(ext->server);
}

struct general {
    char *name;
    char *disabled;
    char *ami;
    char *amihost;
    char *amiport;
    char *amiuser;
    char *amipass;
};

struct trunk {
    char *name;
    char *type;
    char *username;
    char *nr;
    char *password;
    char *codecs;
    char *server;
};

struct model {
    struct list_head *extensions;
    struct general *general;
    struct trunk *trunk;
    sr_subscription_ctx_t *subscription;
};
