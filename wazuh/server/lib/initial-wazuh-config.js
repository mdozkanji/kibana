"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.initialWazuhConfig = void 0;

/*
 * Wazuh app - Initial basic configuration file
 * Copyright (C) 2015-2021 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const initialWazuhConfig = `---
#
# Wazuh app - App configuration file
# Copyright (C) 2015-2021 Wazuh, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Find more information about this on the LICENSE file.
#
# ======================== Wazuh app configuration file ========================
#
# Please check the documentation for more information on configuration options:
# https://documentation.wazuh.com/current/installation-guide/index.html
#
# Also, you can check our repository:
# https://github.com/wazuh/wazuh-kibana-app
#
# ------------------------------- Index patterns -------------------------------
#
# Default index pattern to use.
#pattern: wazuh-alerts-*
#
# ----------------------------------- Checks -----------------------------------
#
# Defines which checks must to be consider by the healthcheck
# step once the Wazuh app starts. Values must to be true or false.
#checks.pattern : true
#checks.template: true
#checks.api     : true
#checks.setup   : true
#checks.metaFields: true
#checks.timeFilter: true
#checks.maxBuckets: true
#
# --------------------------------- Extensions ---------------------------------
#
# Defines which extensions should be activated when you add a new API entry.
# You can change them after Wazuh app starts.
# Values must to be true or false.
#extensions.pci       : true
#extensions.gdpr      : true
#extensions.hipaa     : true
#extensions.nist      : true
#extensions.tsc       : true
#extensions.audit     : true
#extensions.oscap     : false
#extensions.ciscat    : false
#extensions.aws       : false
#extensions.gcp       : false
#extensions.virustotal: false
#extensions.osquery   : false
#extensions.docker    : false
#
# ---------------------------------- Timeout ----------------------------------
#
# Defines maximum timeout to be used on the Wazuh app requests.
# It will be ignored if it is bellow 1500.
# It means milliseconds before we consider a request as failed.
# Default: 20000
#timeout: 20000
#
# -------------------------------- API selector --------------------------------
#
# Defines if the user is allowed to change the selected
# API directly from the Wazuh app top menu.
# Default: true
#api.selector: true
#
# --------------------------- Index pattern selector ---------------------------
#
# Defines if the user is allowed to change the selected
# index pattern directly from the Wazuh app top menu.
# Default: true
#ip.selector: true
#
# List of index patterns to be ignored
#ip.ignore: []
#
# -------------------------------- X-Pack RBAC ---------------------------------
#
# Custom setting to enable/disable built-in X-Pack RBAC security capabilities.
# Default: enabled
#xpack.rbac.enabled: true
#
# ------------------------------ wazuh-monitoring ------------------------------
#
# Custom setting to enable/disable wazuh-monitoring indices.
# Values: true, false, worker
# If worker is given as value, the app will show the Agents status
# visualization but won't insert data on wazuh-monitoring indices.
# Default: true
#wazuh.monitoring.enabled: true
#
# Custom setting to set the frequency for wazuh-monitoring indices cron task.
# Default: 900 (s)
#wazuh.monitoring.frequency: 900
#
# Configure wazuh-monitoring-* indices shards and replicas.
#wazuh.monitoring.shards: 2
#wazuh.monitoring.replicas: 0
#
# Configure wazuh-monitoring-* indices custom creation interval.
# Values: h (hourly), d (daily), w (weekly), m (monthly)
# Default: d
#wazuh.monitoring.creation: d
#
# Default index pattern to use for Wazuh monitoring
#wazuh.monitoring.pattern: wazuh-monitoring-*
#
# --------------------------------- wazuh-cron ----------------------------------
#
# Customize the index prefix of predefined jobs
# This change is not retroactive, if you change it new indexes will be created
# cron.prefix: test
#
# --------------------------------- wazuh-sample-alerts -------------------------
#
# Customize the index name prefix of sample alerts
# This change is not retroactive, if you change it new indexes will be created
# It should match with a valid index template to avoid unknown fields on
# dashboards
#alerts.sample.prefix: wazuh-alerts-4.x-
#
# ------------------------------ wazuh-statistics -------------------------------
#
# Custom setting to enable/disable statistics tasks.
#cron.statistics.status: true
#
# Enter the ID of the APIs you want to save data from, leave this empty to run
# the task on all configured APIs
#cron.statistics.apis: []
#
# Define the frequency of task execution using cron schedule expressions
#cron.statistics.interval: 0 */5 * * * *
#
# Define the name of the index in which the documents are to be saved.
#cron.statistics.index.name: statistics
#
# Define the interval in which the index will be created
#cron.statistics.index.creation: w
#
# Configure statistics indices shards and replicas.
#cron.statistics.shards: 2
#cron.statistics.replicas: 0
#
# ---------------------------- Hide manager alerts ------------------------------
# Hide the alerts of the manager in all dashboards and discover
#hideManagerAlerts: false
#
# ------------------------------- App logging level -----------------------------
# Set the logging level for the Wazuh App log files.
# Default value: info
# Allowed values: info, debug
#logs.level: info
#
# -------------------------------- Enrollment DNS -------------------------------
# Set the variable WAZUH_REGISTRATION_SERVER in agents deployment.
# Default value: ''
#enrollment.dns: ''
#
# Wazuh registration password
# Default value: ''
#enrollment.password: ''
#-------------------------------- API entries -----------------------------------
#The following configuration is the default structure to define an API entry.
#
#hosts:
#  - <id>:
      # URL
      # API url
      # url: http(s)://<url>

      # Port
      # API port
      # port: <port>

      # Username
      # API user's username
      # username: <username>

      # Password
      # API user's password
      # password: <password>

      # Run as
      # Define how the app user gets his/her app permissions.
      # Values:
      #   - true: use his/her authentication context. Require Wazuh API user allows run_as.
      #   - false or not defined: get same permissions of Wazuh API user.
      # run_as: <true|false>
hosts:
  - default:
     url: https://localhost
     port: 55000
     username: wazuh-wui
     password: wazuh-wui
     run_as: false
`;
exports.initialWazuhConfig = initialWazuhConfig;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluaXRpYWwtd2F6dWgtY29uZmlnLnRzIl0sIm5hbWVzIjpbImluaXRpYWxXYXp1aENvbmZpZyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOzs7Ozs7Ozs7OztBQVlPLE1BQU1BLGtCQUEwQixHQUFJOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztDQUFwQyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBJbml0aWFsIGJhc2ljIGNvbmZpZ3VyYXRpb24gZmlsZVxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjEgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuZXhwb3J0IGNvbnN0IGluaXRpYWxXYXp1aENvbmZpZzogc3RyaW5nID0gYC0tLVxuI1xuIyBXYXp1aCBhcHAgLSBBcHAgY29uZmlndXJhdGlvbiBmaWxlXG4jIENvcHlyaWdodCAoQykgMjAxNS0yMDIxIFdhenVoLCBJbmMuXG4jXG4jIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4jIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4jIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4jIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4jXG4jIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4jXG4jID09PT09PT09PT09PT09PT09PT09PT09PSBXYXp1aCBhcHAgY29uZmlndXJhdGlvbiBmaWxlID09PT09PT09PT09PT09PT09PT09PT09PVxuI1xuIyBQbGVhc2UgY2hlY2sgdGhlIGRvY3VtZW50YXRpb24gZm9yIG1vcmUgaW5mb3JtYXRpb24gb24gY29uZmlndXJhdGlvbiBvcHRpb25zOlxuIyBodHRwczovL2RvY3VtZW50YXRpb24ud2F6dWguY29tL2N1cnJlbnQvaW5zdGFsbGF0aW9uLWd1aWRlL2luZGV4Lmh0bWxcbiNcbiMgQWxzbywgeW91IGNhbiBjaGVjayBvdXIgcmVwb3NpdG9yeTpcbiMgaHR0cHM6Ly9naXRodWIuY29tL3dhenVoL3dhenVoLWtpYmFuYS1hcHBcbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBJbmRleCBwYXR0ZXJucyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIERlZmF1bHQgaW5kZXggcGF0dGVybiB0byB1c2UuXG4jcGF0dGVybjogd2F6dWgtYWxlcnRzLSpcbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQ2hlY2tzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIERlZmluZXMgd2hpY2ggY2hlY2tzIG11c3QgdG8gYmUgY29uc2lkZXIgYnkgdGhlIGhlYWx0aGNoZWNrXG4jIHN0ZXAgb25jZSB0aGUgV2F6dWggYXBwIHN0YXJ0cy4gVmFsdWVzIG11c3QgdG8gYmUgdHJ1ZSBvciBmYWxzZS5cbiNjaGVja3MucGF0dGVybiA6IHRydWVcbiNjaGVja3MudGVtcGxhdGU6IHRydWVcbiNjaGVja3MuYXBpICAgICA6IHRydWVcbiNjaGVja3Muc2V0dXAgICA6IHRydWVcbiNjaGVja3MubWV0YUZpZWxkczogdHJ1ZVxuI2NoZWNrcy50aW1lRmlsdGVyOiB0cnVlXG4jY2hlY2tzLm1heEJ1Y2tldHM6IHRydWVcbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEV4dGVuc2lvbnMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIERlZmluZXMgd2hpY2ggZXh0ZW5zaW9ucyBzaG91bGQgYmUgYWN0aXZhdGVkIHdoZW4geW91IGFkZCBhIG5ldyBBUEkgZW50cnkuXG4jIFlvdSBjYW4gY2hhbmdlIHRoZW0gYWZ0ZXIgV2F6dWggYXBwIHN0YXJ0cy5cbiMgVmFsdWVzIG11c3QgdG8gYmUgdHJ1ZSBvciBmYWxzZS5cbiNleHRlbnNpb25zLnBjaSAgICAgICA6IHRydWVcbiNleHRlbnNpb25zLmdkcHIgICAgICA6IHRydWVcbiNleHRlbnNpb25zLmhpcGFhICAgICA6IHRydWVcbiNleHRlbnNpb25zLm5pc3QgICAgICA6IHRydWVcbiNleHRlbnNpb25zLnRzYyAgICAgICA6IHRydWVcbiNleHRlbnNpb25zLmF1ZGl0ICAgICA6IHRydWVcbiNleHRlbnNpb25zLm9zY2FwICAgICA6IGZhbHNlXG4jZXh0ZW5zaW9ucy5jaXNjYXQgICAgOiBmYWxzZVxuI2V4dGVuc2lvbnMuYXdzICAgICAgIDogZmFsc2VcbiNleHRlbnNpb25zLmdjcCAgICAgICA6IGZhbHNlXG4jZXh0ZW5zaW9ucy52aXJ1c3RvdGFsOiBmYWxzZVxuI2V4dGVuc2lvbnMub3NxdWVyeSAgIDogZmFsc2VcbiNleHRlbnNpb25zLmRvY2tlciAgICA6IGZhbHNlXG4jXG4jIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gVGltZW91dCAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIERlZmluZXMgbWF4aW11bSB0aW1lb3V0IHRvIGJlIHVzZWQgb24gdGhlIFdhenVoIGFwcCByZXF1ZXN0cy5cbiMgSXQgd2lsbCBiZSBpZ25vcmVkIGlmIGl0IGlzIGJlbGxvdyAxNTAwLlxuIyBJdCBtZWFucyBtaWxsaXNlY29uZHMgYmVmb3JlIHdlIGNvbnNpZGVyIGEgcmVxdWVzdCBhcyBmYWlsZWQuXG4jIERlZmF1bHQ6IDIwMDAwXG4jdGltZW91dDogMjAwMDBcbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQVBJIHNlbGVjdG9yIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIERlZmluZXMgaWYgdGhlIHVzZXIgaXMgYWxsb3dlZCB0byBjaGFuZ2UgdGhlIHNlbGVjdGVkXG4jIEFQSSBkaXJlY3RseSBmcm9tIHRoZSBXYXp1aCBhcHAgdG9wIG1lbnUuXG4jIERlZmF1bHQ6IHRydWVcbiNhcGkuc2VsZWN0b3I6IHRydWVcbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEluZGV4IHBhdHRlcm4gc2VsZWN0b3IgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIERlZmluZXMgaWYgdGhlIHVzZXIgaXMgYWxsb3dlZCB0byBjaGFuZ2UgdGhlIHNlbGVjdGVkXG4jIGluZGV4IHBhdHRlcm4gZGlyZWN0bHkgZnJvbSB0aGUgV2F6dWggYXBwIHRvcCBtZW51LlxuIyBEZWZhdWx0OiB0cnVlXG4jaXAuc2VsZWN0b3I6IHRydWVcbiNcbiMgTGlzdCBvZiBpbmRleCBwYXR0ZXJucyB0byBiZSBpZ25vcmVkXG4jaXAuaWdub3JlOiBbXVxuI1xuIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBYLVBhY2sgUkJBQyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiNcbiMgQ3VzdG9tIHNldHRpbmcgdG8gZW5hYmxlL2Rpc2FibGUgYnVpbHQtaW4gWC1QYWNrIFJCQUMgc2VjdXJpdHkgY2FwYWJpbGl0aWVzLlxuIyBEZWZhdWx0OiBlbmFibGVkXG4jeHBhY2sucmJhYy5lbmFibGVkOiB0cnVlXG4jXG4jIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSB3YXp1aC1tb25pdG9yaW5nIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuI1xuIyBDdXN0b20gc2V0dGluZyB0byBlbmFibGUvZGlzYWJsZSB3YXp1aC1tb25pdG9yaW5nIGluZGljZXMuXG4jIFZhbHVlczogdHJ1ZSwgZmFsc2UsIHdvcmtlclxuIyBJZiB3b3JrZXIgaXMgZ2l2ZW4gYXMgdmFsdWUsIHRoZSBhcHAgd2lsbCBzaG93IHRoZSBBZ2VudHMgc3RhdHVzXG4jIHZpc3VhbGl6YXRpb24gYnV0IHdvbid0IGluc2VydCBkYXRhIG9uIHdhenVoLW1vbml0b3JpbmcgaW5kaWNlcy5cbiMgRGVmYXVsdDogdHJ1ZVxuI3dhenVoLm1vbml0b3JpbmcuZW5hYmxlZDogdHJ1ZVxuI1xuIyBDdXN0b20gc2V0dGluZyB0byBzZXQgdGhlIGZyZXF1ZW5jeSBmb3Igd2F6dWgtbW9uaXRvcmluZyBpbmRpY2VzIGNyb24gdGFzay5cbiMgRGVmYXVsdDogOTAwIChzKVxuI3dhenVoLm1vbml0b3JpbmcuZnJlcXVlbmN5OiA5MDBcbiNcbiMgQ29uZmlndXJlIHdhenVoLW1vbml0b3JpbmctKiBpbmRpY2VzIHNoYXJkcyBhbmQgcmVwbGljYXMuXG4jd2F6dWgubW9uaXRvcmluZy5zaGFyZHM6IDJcbiN3YXp1aC5tb25pdG9yaW5nLnJlcGxpY2FzOiAwXG4jXG4jIENvbmZpZ3VyZSB3YXp1aC1tb25pdG9yaW5nLSogaW5kaWNlcyBjdXN0b20gY3JlYXRpb24gaW50ZXJ2YWwuXG4jIFZhbHVlczogaCAoaG91cmx5KSwgZCAoZGFpbHkpLCB3ICh3ZWVrbHkpLCBtIChtb250aGx5KVxuIyBEZWZhdWx0OiBkXG4jd2F6dWgubW9uaXRvcmluZy5jcmVhdGlvbjogZFxuI1xuIyBEZWZhdWx0IGluZGV4IHBhdHRlcm4gdG8gdXNlIGZvciBXYXp1aCBtb25pdG9yaW5nXG4jd2F6dWgubW9uaXRvcmluZy5wYXR0ZXJuOiB3YXp1aC1tb25pdG9yaW5nLSpcbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHdhenVoLWNyb24gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuI1xuIyBDdXN0b21pemUgdGhlIGluZGV4IHByZWZpeCBvZiBwcmVkZWZpbmVkIGpvYnNcbiMgVGhpcyBjaGFuZ2UgaXMgbm90IHJldHJvYWN0aXZlLCBpZiB5b3UgY2hhbmdlIGl0IG5ldyBpbmRleGVzIHdpbGwgYmUgY3JlYXRlZFxuIyBjcm9uLnByZWZpeDogdGVzdFxuI1xuIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gd2F6dWgtc2FtcGxlLWFsZXJ0cyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIEN1c3RvbWl6ZSB0aGUgaW5kZXggbmFtZSBwcmVmaXggb2Ygc2FtcGxlIGFsZXJ0c1xuIyBUaGlzIGNoYW5nZSBpcyBub3QgcmV0cm9hY3RpdmUsIGlmIHlvdSBjaGFuZ2UgaXQgbmV3IGluZGV4ZXMgd2lsbCBiZSBjcmVhdGVkXG4jIEl0IHNob3VsZCBtYXRjaCB3aXRoIGEgdmFsaWQgaW5kZXggdGVtcGxhdGUgdG8gYXZvaWQgdW5rbm93biBmaWVsZHMgb25cbiMgZGFzaGJvYXJkc1xuI2FsZXJ0cy5zYW1wbGUucHJlZml4OiB3YXp1aC1hbGVydHMtNC54LVxuI1xuIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gd2F6dWgtc3RhdGlzdGljcyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jXG4jIEN1c3RvbSBzZXR0aW5nIHRvIGVuYWJsZS9kaXNhYmxlIHN0YXRpc3RpY3MgdGFza3MuXG4jY3Jvbi5zdGF0aXN0aWNzLnN0YXR1czogdHJ1ZVxuI1xuIyBFbnRlciB0aGUgSUQgb2YgdGhlIEFQSXMgeW91IHdhbnQgdG8gc2F2ZSBkYXRhIGZyb20sIGxlYXZlIHRoaXMgZW1wdHkgdG8gcnVuXG4jIHRoZSB0YXNrIG9uIGFsbCBjb25maWd1cmVkIEFQSXNcbiNjcm9uLnN0YXRpc3RpY3MuYXBpczogW11cbiNcbiMgRGVmaW5lIHRoZSBmcmVxdWVuY3kgb2YgdGFzayBleGVjdXRpb24gdXNpbmcgY3JvbiBzY2hlZHVsZSBleHByZXNzaW9uc1xuI2Nyb24uc3RhdGlzdGljcy5pbnRlcnZhbDogMCAqLzUgKiAqICogKlxuI1xuIyBEZWZpbmUgdGhlIG5hbWUgb2YgdGhlIGluZGV4IGluIHdoaWNoIHRoZSBkb2N1bWVudHMgYXJlIHRvIGJlIHNhdmVkLlxuI2Nyb24uc3RhdGlzdGljcy5pbmRleC5uYW1lOiBzdGF0aXN0aWNzXG4jXG4jIERlZmluZSB0aGUgaW50ZXJ2YWwgaW4gd2hpY2ggdGhlIGluZGV4IHdpbGwgYmUgY3JlYXRlZFxuI2Nyb24uc3RhdGlzdGljcy5pbmRleC5jcmVhdGlvbjogd1xuI1xuIyBDb25maWd1cmUgc3RhdGlzdGljcyBpbmRpY2VzIHNoYXJkcyBhbmQgcmVwbGljYXMuXG4jY3Jvbi5zdGF0aXN0aWNzLnNoYXJkczogMlxuI2Nyb24uc3RhdGlzdGljcy5yZXBsaWNhczogMFxuI1xuIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEhpZGUgbWFuYWdlciBhbGVydHMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4jIEhpZGUgdGhlIGFsZXJ0cyBvZiB0aGUgbWFuYWdlciBpbiBhbGwgZGFzaGJvYXJkcyBhbmQgZGlzY292ZXJcbiNoaWRlTWFuYWdlckFsZXJ0czogZmFsc2VcbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBBcHAgbG9nZ2luZyBsZXZlbCAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuIyBTZXQgdGhlIGxvZ2dpbmcgbGV2ZWwgZm9yIHRoZSBXYXp1aCBBcHAgbG9nIGZpbGVzLlxuIyBEZWZhdWx0IHZhbHVlOiBpbmZvXG4jIEFsbG93ZWQgdmFsdWVzOiBpbmZvLCBkZWJ1Z1xuI2xvZ3MubGV2ZWw6IGluZm9cbiNcbiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gRW5yb2xsbWVudCBETlMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuIyBTZXQgdGhlIHZhcmlhYmxlIFdBWlVIX1JFR0lTVFJBVElPTl9TRVJWRVIgaW4gYWdlbnRzIGRlcGxveW1lbnQuXG4jIERlZmF1bHQgdmFsdWU6ICcnXG4jZW5yb2xsbWVudC5kbnM6ICcnXG4jXG4jIFdhenVoIHJlZ2lzdHJhdGlvbiBwYXNzd29yZFxuIyBEZWZhdWx0IHZhbHVlOiAnJ1xuI2Vucm9sbG1lbnQucGFzc3dvcmQ6ICcnXG4jLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQVBJIGVudHJpZXMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiNUaGUgZm9sbG93aW5nIGNvbmZpZ3VyYXRpb24gaXMgdGhlIGRlZmF1bHQgc3RydWN0dXJlIHRvIGRlZmluZSBhbiBBUEkgZW50cnkuXG4jXG4jaG9zdHM6XG4jICAtIDxpZD46XG4gICAgICAjIFVSTFxuICAgICAgIyBBUEkgdXJsXG4gICAgICAjIHVybDogaHR0cChzKTovLzx1cmw+XG5cbiAgICAgICMgUG9ydFxuICAgICAgIyBBUEkgcG9ydFxuICAgICAgIyBwb3J0OiA8cG9ydD5cblxuICAgICAgIyBVc2VybmFtZVxuICAgICAgIyBBUEkgdXNlcidzIHVzZXJuYW1lXG4gICAgICAjIHVzZXJuYW1lOiA8dXNlcm5hbWU+XG5cbiAgICAgICMgUGFzc3dvcmRcbiAgICAgICMgQVBJIHVzZXIncyBwYXNzd29yZFxuICAgICAgIyBwYXNzd29yZDogPHBhc3N3b3JkPlxuXG4gICAgICAjIFJ1biBhc1xuICAgICAgIyBEZWZpbmUgaG93IHRoZSBhcHAgdXNlciBnZXRzIGhpcy9oZXIgYXBwIHBlcm1pc3Npb25zLlxuICAgICAgIyBWYWx1ZXM6XG4gICAgICAjICAgLSB0cnVlOiB1c2UgaGlzL2hlciBhdXRoZW50aWNhdGlvbiBjb250ZXh0LiBSZXF1aXJlIFdhenVoIEFQSSB1c2VyIGFsbG93cyBydW5fYXMuXG4gICAgICAjICAgLSBmYWxzZSBvciBub3QgZGVmaW5lZDogZ2V0IHNhbWUgcGVybWlzc2lvbnMgb2YgV2F6dWggQVBJIHVzZXIuXG4gICAgICAjIHJ1bl9hczogPHRydWV8ZmFsc2U+XG5ob3N0czpcbiAgLSBkZWZhdWx0OlxuICAgICB1cmw6IGh0dHBzOi8vbG9jYWxob3N0XG4gICAgIHBvcnQ6IDU1MDAwXG4gICAgIHVzZXJuYW1lOiB3YXp1aC13dWlcbiAgICAgcGFzc3dvcmQ6IHdhenVoLXd1aVxuICAgICBydW5fYXM6IGZhbHNlXG5gXG4iXX0=