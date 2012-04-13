#include <switch.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fail2ban_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_fail2ban_load);

/* SWITCH_MODULE_DEFINITION(name, load, shutdown, runtime) 
 * Defines a switch_loadable_module_function_table_t and a static const char[] modname
 */
SWITCH_MODULE_DEFINITION(mod_fail2ban, mod_fail2ban_load, mod_fail2ban_shutdown, NULL);

char *logfile = "/var/log/freeswitch.log";

static switch_status_t mod_fail2ban_do_config(void);

static switch_xml_t mod_fail2ban_xml_search(const char *section, const char *tag_name, const char *key_name, const char *key_value, switch_event_t *params,
										void *user_data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "XML_SEARCH CALLED!\n");
	
	return NULL;
}

static void shutdown_event_handler(switch_event_t *event)
{

	if (event->event_id == SWITCH_EVENT_CHANNEL_CREATE) {

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event Channel Hangup was called\n");

	} else if (event->event_id == SWITCH_EVENT_CHANNEL_ANSWER) { 
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event answer was called\n");

	} else if (event->event_id == SWITCH_EVENT_CHANNEL_APPLICATION) { 
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event application was called\n");

	}
}

static void shutdown_event_handler(switch_file_t *file, char *log_data)
{
	switch_size_t len;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	len = strlen(log_data);
	
	if (switch_file_write(file, log_data, &len) != SWITCH_STATUS_SUCCESS) {
		switch_file_close(profile->log_afd);
		if ((status = mod_logfile_openlogfile(profile, SWITCH_TRUE)) == SWITCH_STATUS_SUCCESS) {
			len = strlen(log_data);
			switch_file_write(profile->log_afd, log_data, &len);
		}
	}
	return status;
}



/* Macro expands to: switch_status_t mod_fail2ban_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_fail2ban_load)
{
	switch_status_t status;
	switch_event_types_t event = SWITCH_EVENT_ALL;
	const char *subclass_name = SWITCH_EVENT_SUBCLASS_ANY;
	void *user_data = NULL;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	if ((status = switch_event_bind(modname, event, subclass_name, shutdown_event_handler, user_data)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event bind failed\n");
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event bind success\n");
	}


	/* Set the xml search callback. */
	
	if ((status = switch_xml_bind_search_function(mod_fail2ban_xml_search, switch_xml_parse_section_string("directory"), NULL)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "xml search failed\n");
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "xml search success\n");
	}

	
	if (mod_fail2ban_do_config() != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_fail2ban_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fail2ban_shutdown)
{

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_fail2ban_do_config(void)
{
	char *cf = "logfile.conf";
	switch_xml_t cfg, xml, bindings_tag, config = NULL, param = NULL;
	char *var;
	char *val;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	if (!(bindings_tag = switch_xml_child(cfg, "settings"))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing <bindings> tag!\n");
		goto done;
	}
	for (param = switch_xml_child(config, "param"); param; param = param->next) {
		var = (char *) switch_xml_attr_soft(param, "name");
		val = (char *) switch_xml_attr_soft(param, "value");
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: %s\n", var, val);		
		
		if (strncmp(var,"logfile", 7) == 0) {
			logfile = val;
		} else if (strncmp(var,"rotate-on-hup",13) == 0) {
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown attribute %s: %s\n", var, val);		
		}
	}	
	
 done:
	switch_xml_free(xml);
	
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4
 */
