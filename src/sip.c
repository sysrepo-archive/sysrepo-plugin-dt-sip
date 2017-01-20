#include <sys/wait.h>
#include <unistd.h>
#include <uci.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include "sysrepo.h"
#include "sysrepo/plugins.h"

#include "sip.h"
#include "rpc.h"

#define XPATH_MAX_LEN 100
#define UCIPATH_MAX_LEN 100

/* name of the uci config file. */
static const char *config_file = "asterisk";
static const char *module_name = "sip";
static const size_t n_rpc_method = 6;
static const struct rpc_method rpc[] = {
  {"start", rpc_start},
  {"stop", rpc_stop},
  {"restart", rpc_restart},
  {"reload", rpc_reload},
  {"disable", rpc_disable},
  {"enable", rpc_enable},
};

static int
set_value_str(sr_session_ctx_t *sess, char *val_str, char *set_path)
{
  sr_val_t val = { 0, };

  val.type = SR_STRING_T;
  val.data.string_val = val_str;

  int rc = sr_set_item(sess, set_path, &val, SR_EDIT_DEFAULT);

  return rc;
}

/**
 * @brief Submit UCI option.

 * @param[in] ctx Context used for looking up and setting UCI objects.
 * @param[in] str_opt Options key.
 * @param[in] str_val Options value.
 * @param[fmt] fmt Format for path identifier used in UCI.
 * @return UCI error code, UCI_OK on success.
 */
static int
submit_to_uci(struct uci_context *ctx, char *str_opt, char *str_val, char *fmt)
{
  int rc = UCI_OK;
  struct uci_ptr up;
  char ucipath[UCIPATH_MAX_LEN];

  sprintf(ucipath, fmt, str_opt, str_val);

  if ((rc = uci_lookup_ptr(ctx, &up, ucipath, true)) != UCI_OK) {
    fprintf(stderr, "Nothing found on UCI path.\n");
    goto exit;
  }

  if ((rc = uci_set(ctx, &up)) != UCI_OK) {
    fprintf(stderr, "Could not set UCI value [%s] for path [%s].\n", str_val, ucipath);
    goto exit;
  }

 exit:
  return rc;
}

static int
general_to_uci(struct uci_context *ctx, struct general *g)
{
  int rc = UCI_OK;
  char *fmt = "asterisk.@general[0].%s=%s";

  rc = submit_to_uci(ctx, "name", g->name, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "disabled", g->disabled, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "ami", g->ami, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "amihost", g->amihost, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "amiport", g->amiport, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "amiuser", g->amiuser, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "amipass", g->amipass, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }

 exit:
  return rc;
}

static int
trunk_to_uci(struct uci_context *ctx, struct trunk *t)
{
  int rc = UCI_OK;
  char *fmt = "asterisk.terastream.%s=%s";

  rc = submit_to_uci(ctx, "name", t->name, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "type", t->type, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "username", t->username, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "nr", t->nr, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "password", t->password, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "codecs", t->codecs, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }
  rc = submit_to_uci(ctx, "server", t->server, fmt);
  if (UCI_OK != rc) {
    goto exit;
  }

 exit:
  return rc;
}

static int
extensions_to_uci(struct uci_context *ctx, struct list_head *extensions)
{
  int rc = UCI_OK;
  char *fmt = "asterisk.%s.%s=%s"; /* extension name, option name, option value */
  char fmt_named[UCIPATH_MAX_LEN];

  struct extension *ext;
  list_for_each_entry(ext, extensions, head) {

    sprintf(fmt_named, fmt, ext->name, "%s", "%s");

    rc = submit_to_uci(ctx, "name", ext->name, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "type", ext->type, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "context", ext->context, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "target", ext->target, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "external", ext->external, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "international", ext->international, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "trunk", ext->trunk, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "codecs", ext->codecs, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
    rc = submit_to_uci(ctx, "server", ext->server, fmt_named);
    if (UCI_OK != rc) {
      goto exit;
    }
  }

 exit:
  return rc;
}

/**
 * @brief Commit run-time data to UCI configuration files.
 *
 * @param[in] model Model with current run-time data
 * @return UCI error code. UCI_OK on success.
 */
static int
commit_to_uci(struct model *model)
{
  int rc = UCI_OK;

  struct uci_package *up = NULL;
  struct uci_context *ctx = uci_alloc_context();

  rc = uci_load(ctx, "asterisk", &up);
  if (rc != UCI_OK) {
    fprintf(stderr, "No configuration (package): %s\n", "asterisk");
    return rc;
  }

  rc = general_to_uci(ctx, model->general);
  if (UCI_OK != rc) {
    fprintf(stderr, "general_to_uci error %d\n", rc);
  }

  rc = trunk_to_uci(ctx, model->trunk);
  if (UCI_OK != rc) {
    fprintf(stderr, "trunk_to_uci error %d\n", rc);
  }

  rc = extensions_to_uci(ctx, model->extensions);
  if (UCI_OK != rc) {
    fprintf(stderr, "trunk_to_uci error %d\n", rc);
  }

  rc = uci_commit(ctx, &up, false);
  if (UCI_OK != rc) {
    fprintf(stderr, "trunk_to_uci error %d\n", rc);
  }

  return rc;
}

static int
set_values(sr_session_ctx_t *sess, struct general *general, struct list_head *extensions, struct trunk *trunk)
{
  int rc = SR_ERR_OK;
  char xpath[XPATH_MAX_LEN];

  /* Set extensions values. */
  struct extension *ext;
  list_for_each_entry(ext, extensions, head) {
    if (!ext->name || !strcmp("", ext->name) ) break;

    if (ext->type){
      snprintf(xpath,
               XPATH_MAX_LEN, "/sip:extensions/ext[name='%s']/%s",
               ext->name, "type");
      rc = set_value_str(sess, ext->type, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }

    if (ext->context) {
      snprintf(xpath,
               XPATH_MAX_LEN, "/sip:extensions/ext[name='%s']/%s",
               ext->name, "context");
      rc = set_value_str(sess, ext->context, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }

    if (ext->target) {
      snprintf(xpath,
               XPATH_MAX_LEN, "/sip:extensions/ext[name='%s']/%s",
               ext->name, "target");
      rc = set_value_str(sess, ext->target, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }

    if (ext->external) {
      snprintf(xpath,
               XPATH_MAX_LEN, "/sip:extensions/ext[name='%s']/%s",
               ext->name, "external");
      rc = set_value_str(sess, ext->external, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }

    if (ext->international){
      snprintf(xpath, XPATH_MAX_LEN,
               "/sip:extensions/ext[name='%s']/%s",
               ext->name, "international");
      rc = set_value_str(sess, ext->international, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }

    if (ext->trunk){
      snprintf(xpath, XPATH_MAX_LEN,
               "/sip:extensions/ext[name='%s']/%s",
               ext->name, "trunk");
      rc = set_value_str(sess, ext->trunk, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }

    if (ext->codecs){
      snprintf(xpath, XPATH_MAX_LEN,
               "/sip:extensions/ext[name='%s']/%s",
               ext->name, "codecs");
      rc = set_value_str(sess, ext->codecs, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }

    if (ext->server) {
      snprintf(xpath, XPATH_MAX_LEN,
               "/sip:extensions/ext[name='%s']/%s",
               ext->name, "server");
      rc = set_value_str(sess, ext->server, xpath);
      if (SR_ERR_OK != rc) {
        goto cleanup;
      }
    }
  }

  /* Set general values. */
  if (general->name) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:general/%s", "name");
    if (SR_ERR_OK != set_value_str(sess, general->name, xpath)) {
      goto cleanup;
    }
  }

  if (general->disabled) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:general/%s", "disabled");
    if (SR_ERR_OK != set_value_str(sess, general->disabled, xpath)) {
      goto cleanup;
    }
  }

  if (general->ami) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:general/%s", "ami");
    if (SR_ERR_OK != set_value_str(sess, general->ami, xpath)) {
      goto cleanup;
    }
  }

  if (general->amihost) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:general/%s", "amihost");
    if (SR_ERR_OK != set_value_str(sess, general->amihost, xpath)) {
      goto cleanup;
    }
  }

  if (general->amiport) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:general/%s", "amihost");
    if (SR_ERR_OK != set_value_str(sess, general->amiport, xpath)) {
      goto cleanup;
    }
  }

  if (general->amiuser) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:general/%s", "amiuser");
    if (SR_ERR_OK != set_value_str(sess, general->amiuser, xpath)) {
      goto cleanup;
    }
  }

  if (general->amipass) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:general/%s", "amipass");
    if (SR_ERR_OK != set_value_str(sess, general->amipass, xpath)) {
      goto cleanup;
    }
  }

  /* Set trunk values. */
  if (trunk->name) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:trunk/%s", "name");
    if (SR_ERR_OK != set_value_str(sess, trunk->name, xpath)) {
      goto cleanup;
    }
  }

  if (trunk->type) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:trunk/%s", "type");
    if (SR_ERR_OK != set_value_str(sess, trunk->type, xpath)) {
      goto cleanup;
    }
  }

  if (trunk->username) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:trunk/%s", "username");
    if (SR_ERR_OK != set_value_str(sess, trunk->username, xpath)) {
      goto cleanup;
    }
  }

  if (trunk->nr) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:trunk/%s", "nr");
    if (SR_ERR_OK != set_value_str(sess, trunk->nr, xpath)) {
      goto cleanup;
    }
  }

  if (trunk->password) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:trunk/%s", "username");
    if (SR_ERR_OK != set_value_str(sess, trunk->password, xpath)) {
      goto cleanup;
    }
  }

  if (trunk->codecs) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:trunk/%s", "username");
    if (SR_ERR_OK != set_value_str(sess, trunk->codecs, xpath)) {
      goto cleanup;
    }
  }

  if (trunk->server) {
    snprintf(xpath, XPATH_MAX_LEN,
             "/sip:trunk/%s", "username");
    if (SR_ERR_OK != set_value_str(sess, trunk->server, xpath)) {
      goto cleanup;
    }
  }

  rc = sr_commit(sess);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error by sr_commit: %s\n", sr_strerror(rc));
    goto cleanup;
  }

  return SR_ERR_OK;

 cleanup:
  fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
  return rc;
}

/* Fill 'extension' structures with data. */
static int
parse_ext(struct uci_section *s, struct extension *ext)
{
  struct uci_element *e;
  struct uci_option *o;
  char *name, *value;
  int rc = 0;

  ext->name = strdup(s->e.name);

  uci_foreach_element(&s->options, e) {
    o = uci_to_option(e);
    name = o->e.name;
    value = o->v.string;

    if        (!strcmp("name", name)) {
      ext->name = strdup(value);
    } else if (!strcmp("type", name)) {
      ext->type = strdup(value);
    } else if (!strcmp("context", name)) {
      ext->context = strdup(value);
    } else if (!strcmp("target", name)) {
      ext->target = strdup(value);
    } else if (!strcmp("external", name)) {
      ext->external = strdup(value);
    } else if (!strcmp("international", name)) {
      ext->international = strdup(value);
    } else if (!strcmp("trunk", name)) {
      ext->trunk = strdup(value);
    } else if (!strcmp("ring", name)) {
      ext->rings = calloc(1, sizeof(struct ring));
      struct ring rings = { .head = LIST_HEAD_INIT(rings.head),
                            .ring = strdup(value) };
      ext->rings = &rings;
      list_add_tail(&rings.head, &ext->head);
    } else {
      fprintf(stderr, "unexpected option: %s:%s\n", name, value);
      rc = -1;
    }
  }

  return rc;
}

/* Fill 'general' structures with data. */
static int
parse_general(struct uci_section *s, struct general *general)
{
  struct uci_element *e;
  struct uci_option *o;
  char *name, *value;
  int rc = 0;


  uci_foreach_element(&s->options, e) {
    o = uci_to_option(e);
    name = o->e.name;
    value = o->v.string;

    if        (!strcmp("name", name)) {
      general->name = strdup(value);;
    } else if (!strcmp("disabled", name)) {
      general->disabled = "false";
    } else if (!strcmp("ami", name)) {
      general->ami = strdup(value);
    } else if (!strcmp("amihost", name)) {
      general->amihost = strdup(value);
    } else if (!strcmp("amiport", name)) {
      general->amiport = strdup(value);
    } else if (!strcmp("amiuser", name)) {
      general->amiuser = strdup(value);
    } else if (!strcmp("amipass", name)) {
      general->amipass = strdup(value);
    } else {
      fprintf(stderr, "unexpected option: %s:%s\n", name, value);
      rc = -1;
    }
  }

  return rc;
}

/* Fill 'trunk' structures with data. */
static int
parse_trunk(struct uci_section *s, struct trunk *trunk)
{
  struct uci_element *e;
  struct uci_option *o;
  char *name, *value;
  int rc = 0;

  uci_foreach_element(&s->options, e) {
    o = uci_to_option(e);
    name = o->e.name;
    value = o->v.string;

    if        (!strcmp("name", name)) {
      trunk->name = strdup(value);;
    } else if (!strcmp("type", name)) {
      trunk->type = strdup(value);
    } else if (!strcmp("username", name)) {
      trunk->username = strdup(value);
    } else if (!strcmp("nr", name)) {
      trunk->nr = strdup(value);
    } else if (!strcmp("password", name)) {
      trunk->password = strdup(value);
    } else if (!strcmp("codecs", name)) {
      trunk->codecs = strdup(value);
    } else if (!strcmp("server", name)) {
      trunk->server = strdup(value);
    } else {
      fprintf(stderr, "unexpected option: %s:%s\n", name, value);
      rc = -1;
    }
  }

  return rc;
}

/* Fill 'model' with  data from used system. */
static int
init_data(struct uci_context *ctx, struct model *model)
{
  struct uci_package *package = NULL;
  struct uci_element *e;
  struct uci_section *s;
  int rc;
  struct extension *ext;

  rc = uci_load(ctx, config_file, &package);
  if (rc != UCI_OK) {
    fprintf(stderr, "No configuration (package): %s\n", config_file);
    goto out;
  }

  uci_foreach_element(&package->sections, e) {
    s = uci_to_section(e);
    if        (!strcmp(s->type, "ext")) {
      ext = calloc(1, sizeof(*ext));
      parse_ext(s, ext);
      list_add(&ext->head, model->extensions);
    } else if (!strcmp(s->type, "general")) {
      parse_general(s, model->general);
    } else if (!strcmp(s->type, "trunk")) {
      parse_trunk(s, model->trunk);
    } else {
      fprintf(stderr, "Unexpected section: %s\n", s->type);
    }
  }

  return UCI_OK;

 out:
  if (package) {
    uci_unload(ctx, package);
  }
  return rc;
}

static int
init_rpc_cb(sr_session_ctx_t *session, sr_subscription_ctx_t *subscription)
{
  int rc = SR_ERR_OK;
  char path[XPATH_MAX_LEN];

  for (unsigned long i = 0; i < n_rpc_method; i++) {
    snprintf(path, XPATH_MAX_LEN, "/sip:%s", rpc[i].name);
    /* rc = sr_rpc_subscribe(session, path, rpc[i].method, NULL, */
    /*                       SR_SUBSCR_CTX_REUSE, &subscription); */
    /* if (SR_ERR_OK != rc) { */
    /*     break; */
    /* } */
  }

  return rc;
}

int
module_change_cb(sr_session_ctx_t *session, const char *module_name,
                 sr_notif_event_t event, void *private_ctx)
{
  (void) event;
  struct model *model;
  int rc = SR_ERR_OK;

  fprintf(stderr, "module %s has changed\n", module_name);

  /* Handle module changes. */
  model = (struct model *) private_ctx;
  if (!model) {
    fprintf(stderr, "no runtime data available\n");
    goto error;
  }

  rc = commit_to_uci(model);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "commit to UCI configuration files failed.\n");
    goto error;
  }

  return SR_ERR_OK;

 error:
  return rc;
}

static bool
is_datastore_empty(sr_session_ctx_t *session)
{
  sr_val_t *values = NULL;
  size_t count = 0;
  int rc = SR_ERR_OK;
  const char *xpath ="/sip:*//*";

  rc = sr_get_items(session, xpath, &values, &count);

  return SR_ERR_OK == rc ? count == 0 : -1;
}

/* If RUNNING configuration is empty, read configuration from UCI configuration file.
 * If UCI configuration is also empty, leave configuration empty
 */
static int
sync_datastores(sr_session_ctx_t *session, struct model *model, struct uci_context *uci_ctx)
{
  int rc = 0;
  bool empty = false;

  /* check if running datastore is empty  */
  empty = is_datastore_empty(session);

  /* running datastre non-empty */
  if (empty && ((rc = sr_copy_config(session, module_name, SR_DS_RUNNING, SR_DS_STARTUP)) == SR_ERR_OK)) {
    fprintf(stderr, "copying\n" );
    return SR_ERR_OK; /* copy running to startup */
  } else if ((rc = init_data(uci_ctx, model)) != UCI_OK) {
    /* If running is empty than startup is empty so we have to fill it from UCI */
    fprintf(stderr, "Cant initialize data from UCI file.\n");
    return SR_ERR_DATA_MISSING;
  } else {
    fprintf(stdout, "WARNING: Running configuration is empty.\n");
  }

  return SR_ERR_INTERNAL;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
  sr_subscription_ctx_t *subscription = NULL;
  struct uci_context *uci_ctx = NULL;
  struct model *model = NULL;
  int rc = SR_ERR_OK;

  /* Initialize module change handlers. */
  rc = sr_module_change_subscribe(session, "sip", module_change_cb, NULL,
                                  0, SR_SUBSCR_DEFAULT, &subscription);
  if (SR_ERR_OK != rc) {
      goto error;
  }

  /* Initialize rpc handlers. */
  rc = init_rpc_cb(session, subscription);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error initializing rpc methods: %s\n", sr_strerror(rc));
    goto error;
  }

  /* Allocate UCI context for uci files. */
  uci_ctx = uci_alloc_context();
  if (!uci_ctx) {
    fprintf(stderr, "Can't allocate uci\n");
    goto error;
  }

  struct list_head extensions = LIST_HEAD_INIT(extensions);
  struct trunk *trunk = calloc(1, sizeof(*trunk));
  struct general *general = calloc(1, sizeof(*general));

  model = calloc(1, sizeof(*model));
  model->extensions = &extensions;
  model->general = general;
  model->trunk = trunk;

  /* Startup datastore is main one, if it is empty fill config from UCI file. */
  /* If UCI file is empty, run without initialized data. */
  rc = sync_datastores(session, model, uci_ctx);

  /* Commit values to datastore. */
  set_values(session, model->general, model->extensions, model->trunk);

  uci_free_context(uci_ctx);

  *private_ctx = model;
  return SR_ERR_OK;

 error:
  if (subscription) {
    sr_unsubscribe(session, subscription);
  }
  if (uci_ctx) {
    uci_free_context(uci_ctx);
  }
  if (model) {
    free(model);
  }

  return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
  struct model *m;

  fprintf(stderr, "Plugin cleanup...\n");

  if (private_ctx) {
    m = (struct model *) private_ctx;
    sr_unsubscribe(session, m->subscription);
    free(m);
  }
}

#ifdef TESTS
volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
  fprintf(stderr, "Sigint called, exiting...\n");
  exit_application = 1;
}

int
main(int argc, char *argv[])
{
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  int rc = SR_ERR_OK;

  /* connect to sysrepo */
  rc = sr_connect("sip", SR_CONN_DEFAULT, &connection);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
    goto cleanup;
  }

  /* start session */
  rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
    goto cleanup;
  }

  void *private_ctx = NULL;
  sr_plugin_init_cb(session, &private_ctx);

  /* loop until ctrl-c is pressed / SIGINT is received */
  signal(SIGINT, sigint_handler);
  signal(SIGPIPE, SIG_IGN);
  while (!exit_application) {
    sleep(1000);  /* or do some more useful work... */
  }

 cleanup:
  sr_plugin_cleanup_cb(session, private_ctx);
}
#endif
