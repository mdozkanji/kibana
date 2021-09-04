"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.AgentConfiguration = void 0;

/*
 * Wazuh app - Agent configuration request objet for exporting it
 * Copyright (C) 2015-2021 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const AgentConfiguration = {
  configurations: [{
    title: 'Main configurations',
    sections: [{
      subtitle: 'Global configuration',
      desc: 'Logging settings that apply to the agent',
      config: [{
        component: 'com',
        configuration: 'logging'
      }],
      labels: [{
        plain: 'Write internal logs in plain text',
        json: 'Write internal logs in JSON format',
        server: 'List of managers to connect'
      }]
    }, {
      subtitle: 'Communication',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html',
      desc: 'Settings related to the connection with the manager',
      config: [{
        component: 'agent',
        configuration: 'client'
      }],
      labels: [{
        crypto_method: 'Method used to encrypt communications',
        auto_restart: 'Auto-restart the agent when receiving valid configuration from manager',
        notify_time: 'Time (in seconds) between agent checkings to the manager',
        'time-reconnect': 'Time (in seconds) before attempting to reconnect',
        server: 'List of managers to connect',
        'config-profile': 'Configuration profiles',
        remote_conf: 'Remote configuration is enabled'
      }]
    }, {
      subtitle: 'Anti-flooding settings',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/capabilities/antiflooding.html',
      desc: 'Agent bucket parameters to avoid event flooding',
      config: [{
        component: 'agent',
        configuration: 'buffer'
      }],
      labels: [{
        disabled: 'Buffer disabled',
        queue_size: 'Queue size',
        events_per_second: 'Events per second'
      }]
    }, {
      subtitle: 'Labels',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/labels.html',
      desc: 'User-defined information about the agent included in alerts',
      config: [{
        component: 'agent',
        configuration: 'labels'
      }]
    }]
  }, {
    title: 'Auditing and policy monitoring',
    sections: [{
      subtitle: 'Policy monitoring',
      docuLink: 'https://documentation.wazuh.com/current/pci-dss/policy-monitoring.html',
      desc: 'Configuration to ensure compliance with security policies, standards and hardening guides',
      config: [{
        component: 'syscheck',
        configuration: 'rootcheck'
      }],
      wodle: [{
        name: 'sca'
      }],
      labels: [{
        disabled: 'Policy monitoring service disabled',
        base_directory: 'Base directory',
        rootkit_files: 'Rootkit files database path',
        rootkit_trojans: 'Rootkit trojans database path',
        scanall: 'Scan the entire system',
        skip_nfs: 'Skip scan on CIFS/NFS mounts',
        frequency: 'Frequency (in seconds) to run the scan',
        check_dev: 'Check /dev path',
        check_files: 'Check files',
        check_if: 'Check network interfaces',
        check_pids: 'Check processes IDs',
        check_ports: 'Check network ports',
        check_sys: 'Check anomalous system objects',
        check_trojans: 'Check trojans',
        check_unixaudit: 'Check UNIX audit',
        system_audit: 'UNIX audit files paths',
        enabled: 'Security configuration assessment enabled',
        scan_on_start: 'Scan on start',
        interval: 'Interval',
        policies: 'Policies'
      }],
      tabs: ['General', 'Security configuration assessment']
    }, {
      subtitle: 'OpenSCAP',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-openscap.html',
      desc: 'Configuration assessment and automation of compliance monitoring using SCAP checks',
      wodle: [{
        name: 'open-scap'
      }],
      labels: [{
        content: 'Evaluations',
        disabled: 'OpenSCAP integration disabled',
        'scan-on-start': 'Scan on start',
        interval: 'Interval between scan executions',
        timeout: 'Timeout (in seconds) for scan executions'
      }]
    }, {
      subtitle: 'CIS-CAT',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-ciscat.html',
      desc: 'Configuration assessment using CIS scanner and SCAP checks',
      wodle: [{
        name: 'cis-cat'
      }],
      labels: [{
        disabled: 'CIS-CAT integration disabled',
        'scan-on-start': 'Scan on start',
        interval: 'Interval between scan executions',
        java_path: 'Path to Java executable directory',
        ciscat_path: 'Path to CIS-CAT executable directory',
        timeout: 'Timeout (in seconds) for scan executions',
        content: 'Benchmarks'
      }]
    }]
  }, {
    title: 'System threats and incident response',
    sections: [{
      subtitle: 'Osquery',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-osquery.html',
      desc: 'Expose an operating system as a high-performance relational database',
      wodle: [{
        name: 'osquery'
      }],
      labels: [{
        disabled: 'Osquery integration disabled',
        run_daemon: 'Auto-run the Osquery daemon',
        add_labels: 'Use defined labels as decorators',
        log_path: 'Path to the Osquery results log file',
        config_path: 'Path to the Osquery configuration file'
      }]
    }, {
      subtitle: 'Inventory data',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-syscollector.html',
      desc: 'Gather relevant information about system OS, hardware, networking and packages',
      wodle: [{
        name: 'syscollector'
      }],
      labels: [{
        disabled: 'Syscollector integration disabled',
        'scan-on-start': 'Scan on start',
        interval: 'Interval between system scans',
        network: 'Scan network interfaces',
        os: 'Scan operating system info',
        hardware: 'Scan hardware info',
        packages: 'Scan installed packages',
        ports: 'Scan listening network ports',
        ports_all: 'Scan all network ports',
        processes: 'Scan current processes'
      }]
    }, {
      subtitle: 'Active response',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html',
      desc: 'Active threat addressing by immediate response',
      config: [{
        component: 'com',
        configuration: 'active-response'
      }],
      labels: [{
        disabled: 'Active response disabled',
        ca_store: 'Use the following list of root CA certificates',
        ca_verification: 'Validate WPKs using root CA certificate'
      }]
    }, {
      subtitle: 'Commands',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html',
      desc: 'Configuration options of the Command wodle',
      wodle: [{
        name: 'command'
      }],
      labels: [{
        disabled: 'Command disabled',
        run_on_start: 'Run on start',
        ignore_output: 'Ignore command output',
        skip_verification: 'Ignore checksum verification',
        interval: 'Interval between executions',
        tag: 'Command name',
        command: 'Command to execute',
        verify_md5: 'Verify MD5 sum',
        verify_sha1: 'Verify SHA1 sum',
        verify_sha256: 'Verify SHA256 sum'
      }]
    }, {
      subtitle: 'Docker listener',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-docker.html',
      desc: 'Monitor and collect the activity from Docker containers such as creation, running, starting, stopping or pausing events',
      wodle: [{
        name: 'docker-listener'
      }],
      labels: [{
        disabled: 'Docker listener disabled',
        run_on_start: 'Run the listener immediately when service is started',
        interval: 'Waiting time to rerun the listener in case it fails',
        attempts: 'Number of attempts to execute the listener'
      }]
    }]
  }, {
    title: 'Log data analysis',
    sections: [{
      subtitle: 'Log collection',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html',
      desc: 'Log analysis from text files, Windows events or syslog outputs',
      config: [{
        component: 'logcollector',
        configuration: 'localfile',
        filterBy: 'logformat'
      }, {
        component: 'logcollector',
        configuration: 'socket'
      }],
      labels: [{
        logformat: 'Log format',
        log_format: 'Log format',
        alias: 'Command alias',
        ignore_binaries: 'Ignore binaries',
        target: 'Redirect output to this socket',
        frequency: 'Interval between command executions',
        file: 'Log location',
        location: 'Log location',
        socket: 'Output sockets',
        syslog: 'Syslog',
        command: 'Command',
        full_command: 'Full command',
        audit: 'Audit'
      }],
      options: {
        hideHeader: true
      }
    }, {
      subtitle: 'Integrity monitoring',
      docuLink: 'https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html',
      desc: 'Identify changes in content, permissions, ownership, and attributes of files',
      config: [{
        component: 'syscheck',
        configuration: 'syscheck',
        matrix: true
      }],
      tabs: ['General', 'Who data'],
      labels: [{
        disabled: 'Integrity monitoring disabled',
        frequency: 'Interval (in seconds) to run the integrity scan',
        skip_nfs: 'Skip scan on CIFS/NFS mounts',
        scan_on_start: 'Scan on start',
        directories: 'Monitored directories',
        nodiff: 'No diff directories',
        ignore: 'Ignored files and directories',
        restart_audit: 'Restart audit',
        startup_healthcheck: 'Startup healthcheck'
      }],
      opts: {
        realtime: 'RT',
        check_whodata: 'WD',
        report_changes: 'Changes',
        check_md5sum: 'MD5',
        check_sha1sum: 'SHA1',
        check_perm: 'Per.',
        check_size: 'Size',
        check_owner: 'Owner',
        check_group: 'Group',
        check_mtime: 'MT',
        check_inode: 'Inode',
        check_sha256sum: 'SHA256',
        follow_symbolic_link: 'SL'
      }
    }]
  }]
};
exports.AgentConfiguration = AgentConfiguration;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50LWNvbmZpZ3VyYXRpb24udHMiXSwibmFtZXMiOlsiQWdlbnRDb25maWd1cmF0aW9uIiwiY29uZmlndXJhdGlvbnMiLCJ0aXRsZSIsInNlY3Rpb25zIiwic3VidGl0bGUiLCJkZXNjIiwiY29uZmlnIiwiY29tcG9uZW50IiwiY29uZmlndXJhdGlvbiIsImxhYmVscyIsInBsYWluIiwianNvbiIsInNlcnZlciIsImRvY3VMaW5rIiwiY3J5cHRvX21ldGhvZCIsImF1dG9fcmVzdGFydCIsIm5vdGlmeV90aW1lIiwicmVtb3RlX2NvbmYiLCJkaXNhYmxlZCIsInF1ZXVlX3NpemUiLCJldmVudHNfcGVyX3NlY29uZCIsIndvZGxlIiwibmFtZSIsImJhc2VfZGlyZWN0b3J5Iiwicm9vdGtpdF9maWxlcyIsInJvb3RraXRfdHJvamFucyIsInNjYW5hbGwiLCJza2lwX25mcyIsImZyZXF1ZW5jeSIsImNoZWNrX2RldiIsImNoZWNrX2ZpbGVzIiwiY2hlY2tfaWYiLCJjaGVja19waWRzIiwiY2hlY2tfcG9ydHMiLCJjaGVja19zeXMiLCJjaGVja190cm9qYW5zIiwiY2hlY2tfdW5peGF1ZGl0Iiwic3lzdGVtX2F1ZGl0IiwiZW5hYmxlZCIsInNjYW5fb25fc3RhcnQiLCJpbnRlcnZhbCIsInBvbGljaWVzIiwidGFicyIsImNvbnRlbnQiLCJ0aW1lb3V0IiwiamF2YV9wYXRoIiwiY2lzY2F0X3BhdGgiLCJydW5fZGFlbW9uIiwiYWRkX2xhYmVscyIsImxvZ19wYXRoIiwiY29uZmlnX3BhdGgiLCJuZXR3b3JrIiwib3MiLCJoYXJkd2FyZSIsInBhY2thZ2VzIiwicG9ydHMiLCJwb3J0c19hbGwiLCJwcm9jZXNzZXMiLCJjYV9zdG9yZSIsImNhX3ZlcmlmaWNhdGlvbiIsInJ1bl9vbl9zdGFydCIsImlnbm9yZV9vdXRwdXQiLCJza2lwX3ZlcmlmaWNhdGlvbiIsInRhZyIsImNvbW1hbmQiLCJ2ZXJpZnlfbWQ1IiwidmVyaWZ5X3NoYTEiLCJ2ZXJpZnlfc2hhMjU2IiwiYXR0ZW1wdHMiLCJmaWx0ZXJCeSIsImxvZ2Zvcm1hdCIsImxvZ19mb3JtYXQiLCJhbGlhcyIsImlnbm9yZV9iaW5hcmllcyIsInRhcmdldCIsImZpbGUiLCJsb2NhdGlvbiIsInNvY2tldCIsInN5c2xvZyIsImZ1bGxfY29tbWFuZCIsImF1ZGl0Iiwib3B0aW9ucyIsImhpZGVIZWFkZXIiLCJtYXRyaXgiLCJkaXJlY3RvcmllcyIsIm5vZGlmZiIsImlnbm9yZSIsInJlc3RhcnRfYXVkaXQiLCJzdGFydHVwX2hlYWx0aGNoZWNrIiwib3B0cyIsInJlYWx0aW1lIiwiY2hlY2tfd2hvZGF0YSIsInJlcG9ydF9jaGFuZ2VzIiwiY2hlY2tfbWQ1c3VtIiwiY2hlY2tfc2hhMXN1bSIsImNoZWNrX3Blcm0iLCJjaGVja19zaXplIiwiY2hlY2tfb3duZXIiLCJjaGVja19ncm91cCIsImNoZWNrX210aW1lIiwiY2hlY2tfaW5vZGUiLCJjaGVja19zaGEyNTZzdW0iLCJmb2xsb3dfc3ltYm9saWNfbGluayJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOzs7Ozs7Ozs7OztBQVdPLE1BQU1BLGtCQUFrQixHQUFHO0FBQ2hDQyxFQUFBQSxjQUFjLEVBQUUsQ0FDZDtBQUNFQyxJQUFBQSxLQUFLLEVBQUUscUJBRFQ7QUFFRUMsSUFBQUEsUUFBUSxFQUFFLENBQ1I7QUFDRUMsTUFBQUEsUUFBUSxFQUFFLHNCQURaO0FBRUVDLE1BQUFBLElBQUksRUFBRSwwQ0FGUjtBQUdFQyxNQUFBQSxNQUFNLEVBQUUsQ0FBQztBQUFFQyxRQUFBQSxTQUFTLEVBQUUsS0FBYjtBQUFvQkMsUUFBQUEsYUFBYSxFQUFFO0FBQW5DLE9BQUQsQ0FIVjtBQUlFQyxNQUFBQSxNQUFNLEVBQUUsQ0FDTjtBQUNFQyxRQUFBQSxLQUFLLEVBQUUsbUNBRFQ7QUFFRUMsUUFBQUEsSUFBSSxFQUFFLG9DQUZSO0FBR0VDLFFBQUFBLE1BQU0sRUFBRTtBQUhWLE9BRE07QUFKVixLQURRLEVBYVI7QUFDRVIsTUFBQUEsUUFBUSxFQUFFLGVBRFo7QUFF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M0IiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gQWdlbnQgY29uZmlndXJhdGlvbiByZXF1ZXN0IG9iamV0IGZvciBleHBvcnRpbmcgaXRcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIxIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgY29uc3QgQWdlbnRDb25maWd1cmF0aW9uID0ge1xuICBjb25maWd1cmF0aW9uczogW1xuICAgIHtcbiAgICAgIHRpdGxlOiAnTWFpbiBjb25maWd1cmF0aW9ucycsXG4gICAgICBzZWN0aW9uczogW1xuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdHbG9iYWwgY29uZmlndXJhdGlvbicsXG4gICAgICAgICAgZGVzYzogJ0xvZ2dpbmcgc2V0dGluZ3MgdGhhdCBhcHBseSB0byB0aGUgYWdlbnQnLFxuICAgICAgICAgIGNvbmZpZzogW3sgY29tcG9uZW50OiAnY29tJywgY29uZmlndXJhdGlvbjogJ2xvZ2dpbmcnIH1dLFxuICAgICAgICAgIGxhYmVsczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBwbGFpbjogJ1dyaXRlIGludGVybmFsIGxvZ3MgaW4gcGxhaW4gdGV4dCcsXG4gICAgICAgICAgICAgIGpzb246ICdXcml0ZSBpbnRlcm5hbCBsb2dzIGluIEpTT04gZm9ybWF0JyxcbiAgICAgICAgICAgICAgc2VydmVyOiAnTGlzdCBvZiBtYW5hZ2VycyB0byBjb25uZWN0J1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnQ29tbXVuaWNhdGlvbicsXG4gICAgICAgICAgZG9jdUxpbms6XG4gICAgICAgICAgICAnaHR0cHM6Ly9kb2N1bWVudGF0aW9uLndhenVoLmNvbS9jdXJyZW50L3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL2NsaWVudC5odG1sJyxcbiAgICAgICAgICBkZXNjOiAnU2V0dGluZ3MgcmVsYXRlZCB0byB0aGUgY29ubmVjdGlvbiB3aXRoIHRoZSBtYW5hZ2VyJyxcbiAgICAgICAgICBjb25maWc6IFt7IGNvbXBvbmVudDogJ2FnZW50JywgY29uZmlndXJhdGlvbjogJ2NsaWVudCcgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGNyeXB0b19tZXRob2Q6ICdNZXRob2QgdXNlZCB0byBlbmNyeXB0IGNvbW11bmljYXRpb25zJyxcbiAgICAgICAgICAgICAgYXV0b19yZXN0YXJ0OlxuICAgICAgICAgICAgICAgICdBdXRvLXJlc3RhcnQgdGhlIGFnZW50IHdoZW4gcmVjZWl2aW5nIHZhbGlkIGNvbmZpZ3VyYXRpb24gZnJvbSBtYW5hZ2VyJyxcbiAgICAgICAgICAgICAgbm90aWZ5X3RpbWU6XG4gICAgICAgICAgICAgICAgJ1RpbWUgKGluIHNlY29uZHMpIGJldHdlZW4gYWdlbnQgY2hlY2tpbmdzIHRvIHRoZSBtYW5hZ2VyJyxcbiAgICAgICAgICAgICAgJ3RpbWUtcmVjb25uZWN0JzpcbiAgICAgICAgICAgICAgICAnVGltZSAoaW4gc2Vjb25kcykgYmVmb3JlIGF0dGVtcHRpbmcgdG8gcmVjb25uZWN0JyxcbiAgICAgICAgICAgICAgc2VydmVyOiAnTGlzdCBvZiBtYW5hZ2VycyB0byBjb25uZWN0JyxcbiAgICAgICAgICAgICAgJ2NvbmZpZy1wcm9maWxlJzogJ0NvbmZpZ3VyYXRpb24gcHJvZmlsZXMnLFxuICAgICAgICAgICAgICByZW1vdGVfY29uZjogJ1JlbW90ZSBjb25maWd1cmF0aW9uIGlzIGVuYWJsZWQnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdBbnRpLWZsb29kaW5nIHNldHRpbmdzJyxcbiAgICAgICAgICBkb2N1TGluazpcbiAgICAgICAgICAgICdodHRwczovL2RvY3VtZW50YXRpb24ud2F6dWguY29tL2N1cnJlbnQvdXNlci1tYW51YWwvY2FwYWJpbGl0aWVzL2FudGlmbG9vZGluZy5odG1sJyxcbiAgICAgICAgICBkZXNjOiAnQWdlbnQgYnVja2V0IHBhcmFtZXRlcnMgdG8gYXZvaWQgZXZlbnQgZmxvb2RpbmcnLFxuICAgICAgICAgIGNvbmZpZzogW3sgY29tcG9uZW50OiAnYWdlbnQnLCBjb25maWd1cmF0aW9uOiAnYnVmZmVyJyB9XSxcbiAgICAgICAgICBsYWJlbHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgZGlzYWJsZWQ6ICdCdWZmZXIgZGlzYWJsZWQnLFxuICAgICAgICAgICAgICBxdWV1ZV9zaXplOiAnUXVldWUgc2l6ZScsXG4gICAgICAgICAgICAgIGV2ZW50c19wZXJfc2Vjb25kOiAnRXZlbnRzIHBlciBzZWNvbmQnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdMYWJlbHMnLFxuICAgICAgICAgIGRvY3VMaW5rOlxuICAgICAgICAgICAgJ2h0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20vY3VycmVudC91c2VyLW1hbnVhbC9yZWZlcmVuY2Uvb3NzZWMtY29uZi9sYWJlbHMuaHRtbCcsXG4gICAgICAgICAgZGVzYzogJ1VzZXItZGVmaW5lZCBpbmZvcm1hdGlvbiBhYm91dCB0aGUgYWdlbnQgaW5jbHVkZWQgaW4gYWxlcnRzJyxcbiAgICAgICAgICBjb25maWc6IFt7IGNvbXBvbmVudDogJ2FnZW50JywgY29uZmlndXJhdGlvbjogJ2xhYmVscycgfV1cbiAgICAgICAgfVxuICAgICAgXVxuICAgIH0sXG4gICAge1xuICAgICAgdGl0bGU6ICdBdWRpdGluZyBhbmQgcG9saWN5IG1vbml0b3JpbmcnLFxuICAgICAgc2VjdGlvbnM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnUG9saWN5IG1vbml0b3JpbmcnLFxuICAgICAgICAgIGRvY3VMaW5rOlxuICAgICAgICAgICAgJ2h0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20vY3VycmVudC9wY2ktZHNzL3BvbGljeS1tb25pdG9yaW5nLmh0bWwnLFxuICAgICAgICAgIGRlc2M6XG4gICAgICAgICAgICAnQ29uZmlndXJhdGlvbiB0byBlbnN1cmUgY29tcGxpYW5jZSB3aXRoIHNlY3VyaXR5IHBvbGljaWVzLCBzdGFuZGFyZHMgYW5kIGhhcmRlbmluZyBndWlkZXMnLFxuICAgICAgICAgIGNvbmZpZzogW3sgY29tcG9uZW50OiAnc3lzY2hlY2snLCBjb25maWd1cmF0aW9uOiAncm9vdGNoZWNrJyB9XSxcbiAgICAgICAgICB3b2RsZTogW3sgbmFtZTogJ3NjYScgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnUG9saWN5IG1vbml0b3Jpbmcgc2VydmljZSBkaXNhYmxlZCcsXG4gICAgICAgICAgICAgIGJhc2VfZGlyZWN0b3J5OiAnQmFzZSBkaXJlY3RvcnknLFxuICAgICAgICAgICAgICByb290a2l0X2ZpbGVzOiAnUm9vdGtpdCBmaWxlcyBkYXRhYmFzZSBwYXRoJyxcbiAgICAgICAgICAgICAgcm9vdGtpdF90cm9qYW5zOiAnUm9vdGtpdCB0cm9qYW5zIGRhdGFiYXNlIHBhdGgnLFxuICAgICAgICAgICAgICBzY2FuYWxsOiAnU2NhbiB0aGUgZW50aXJlIHN5c3RlbScsXG4gICAgICAgICAgICAgIHNraXBfbmZzOiAnU2tpcCBzY2FuIG9uIENJRlMvTkZTIG1vdW50cycsXG4gICAgICAgICAgICAgIGZyZXF1ZW5jeTogJ0ZyZXF1ZW5jeSAoaW4gc2Vjb25kcykgdG8gcnVuIHRoZSBzY2FuJyxcbiAgICAgICAgICAgICAgY2hlY2tfZGV2OiAnQ2hlY2sgL2RldiBwYXRoJyxcbiAgICAgICAgICAgICAgY2hlY2tfZmlsZXM6ICdDaGVjayBmaWxlcycsXG4gICAgICAgICAgICAgIGNoZWNrX2lmOiAnQ2hlY2sgbmV0d29yayBpbnRlcmZhY2VzJyxcbiAgICAgICAgICAgICAgY2hlY2tfcGlkczogJ0NoZWNrIHByb2Nlc3NlcyBJRHMnLFxuICAgICAgICAgICAgICBjaGVja19wb3J0czogJ0NoZWNrIG5ldHdvcmsgcG9ydHMnLFxuICAgICAgICAgICAgICBjaGVja19zeXM6ICdDaGVjayBhbm9tYWxvdXMgc3lzdGVtIG9iamVjdHMnLFxuICAgICAgICAgICAgICBjaGVja190cm9qYW5zOiAnQ2hlY2sgdHJvamFucycsXG4gICAgICAgICAgICAgIGNoZWNrX3VuaXhhdWRpdDogJ0NoZWNrIFVOSVggYXVkaXQnLFxuICAgICAgICAgICAgICBzeXN0ZW1fYXVkaXQ6ICdVTklYIGF1ZGl0IGZpbGVzIHBhdGhzJyxcbiAgICAgICAgICAgICAgZW5hYmxlZDogJ1NlY3VyaXR5IGNvbmZpZ3VyYXRpb24gYXNzZXNzbWVudCBlbmFibGVkJyxcbiAgICAgICAgICAgICAgc2Nhbl9vbl9zdGFydDogJ1NjYW4gb24gc3RhcnQnLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ0ludGVydmFsJyxcbiAgICAgICAgICAgICAgcG9saWNpZXM6ICdQb2xpY2llcydcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIHRhYnM6IFsnR2VuZXJhbCcsICdTZWN1cml0eSBjb25maWd1cmF0aW9uIGFzc2Vzc21lbnQnXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdPcGVuU0NBUCcsXG4gICAgICAgICAgZG9jdUxpbms6XG4gICAgICAgICAgICAnaHR0cHM6Ly9kb2N1bWVudGF0aW9uLndhenVoLmNvbS9jdXJyZW50L3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL3dvZGxlLW9wZW5zY2FwLmh0bWwnLFxuICAgICAgICAgIGRlc2M6XG4gICAgICAgICAgICAnQ29uZmlndXJhdGlvbiBhc3Nlc3NtZW50IGFuZCBhdXRvbWF0aW9uIG9mIGNvbXBsaWFuY2UgbW9uaXRvcmluZyB1c2luZyBTQ0FQIGNoZWNrcycsXG4gICAgICAgICAgd29kbGU6IFt7IG5hbWU6ICdvcGVuLXNjYXAnIH1dLFxuICAgICAgICAgIGxhYmVsczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBjb250ZW50OiAnRXZhbHVhdGlvbnMnLFxuICAgICAgICAgICAgICBkaXNhYmxlZDogJ09wZW5TQ0FQIGludGVncmF0aW9uIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgJ3NjYW4tb24tc3RhcnQnOiAnU2NhbiBvbiBzdGFydCcsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnSW50ZXJ2YWwgYmV0d2VlbiBzY2FuIGV4ZWN1dGlvbnMnLFxuICAgICAgICAgICAgICB0aW1lb3V0OiAnVGltZW91dCAoaW4gc2Vjb25kcykgZm9yIHNjYW4gZXhlY3V0aW9ucydcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdWJ0aXRsZTogJ0NJUy1DQVQnLFxuICAgICAgICAgIGRvY3VMaW5rOlxuICAgICAgICAgICAgJ2h0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20vY3VycmVudC91c2VyLW1hbnVhbC9yZWZlcmVuY2Uvb3NzZWMtY29uZi93b2RsZS1jaXNjYXQuaHRtbCcsXG4gICAgICAgICAgZGVzYzogJ0NvbmZpZ3VyYXRpb24gYXNzZXNzbWVudCB1c2luZyBDSVMgc2Nhbm5lciBhbmQgU0NBUCBjaGVja3MnLFxuICAgICAgICAgIHdvZGxlOiBbeyBuYW1lOiAnY2lzLWNhdCcgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnQ0lTLUNBVCBpbnRlZ3JhdGlvbiBkaXNhYmxlZCcsXG4gICAgICAgICAgICAgICdzY2FuLW9uLXN0YXJ0JzogJ1NjYW4gb24gc3RhcnQnLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ0ludGVydmFsIGJldHdlZW4gc2NhbiBleGVjdXRpb25zJyxcbiAgICAgICAgICAgICAgamF2YV9wYXRoOiAnUGF0aCB0byBKYXZhIGV4ZWN1dGFibGUgZGlyZWN0b3J5JyxcbiAgICAgICAgICAgICAgY2lzY2F0X3BhdGg6ICdQYXRoIHRvIENJUy1DQVQgZXhlY3V0YWJsZSBkaXJlY3RvcnknLFxuICAgICAgICAgICAgICB0aW1lb3V0OiAnVGltZW91dCAoaW4gc2Vjb25kcykgZm9yIHNjYW4gZXhlY3V0aW9ucycsXG4gICAgICAgICAgICAgIGNvbnRlbnQ6ICdCZW5jaG1hcmtzJ1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfVxuICAgICAgXVxuICAgIH0sXG4gICAge1xuICAgICAgdGl0bGU6ICdTeXN0ZW0gdGhyZWF0cyBhbmQgaW5jaWRlbnQgcmVzcG9uc2UnLFxuICAgICAgc2VjdGlvbnM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnT3NxdWVyeScsXG4gICAgICAgICAgZG9jdUxpbms6XG4gICAgICAgICAgICAnaHR0cHM6Ly9kb2N1bWVudGF0aW9uLndhenVoLmNvbS9jdXJyZW50L3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL3dvZGxlLW9zcXVlcnkuaHRtbCcsXG4gICAgICAgICAgZGVzYzpcbiAgICAgICAgICAgICdFeHBvc2UgYW4gb3BlcmF0aW5nIHN5c3RlbSBhcyBhIGhpZ2gtcGVyZm9ybWFuY2UgcmVsYXRpb25hbCBkYXRhYmFzZScsXG4gICAgICAgICAgd29kbGU6IFt7IG5hbWU6ICdvc3F1ZXJ5JyB9XSxcbiAgICAgICAgICBsYWJlbHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgZGlzYWJsZWQ6ICdPc3F1ZXJ5IGludGVncmF0aW9uIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgcnVuX2RhZW1vbjogJ0F1dG8tcnVuIHRoZSBPc3F1ZXJ5IGRhZW1vbicsXG4gICAgICAgICAgICAgIGFkZF9sYWJlbHM6ICdVc2UgZGVmaW5lZCBsYWJlbHMgYXMgZGVjb3JhdG9ycycsXG4gICAgICAgICAgICAgIGxvZ19wYXRoOiAnUGF0aCB0byB0aGUgT3NxdWVyeSByZXN1bHRzIGxvZyBmaWxlJyxcbiAgICAgICAgICAgICAgY29uZmlnX3BhdGg6ICdQYXRoIHRvIHRoZSBPc3F1ZXJ5IGNvbmZpZ3VyYXRpb24gZmlsZSdcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdWJ0aXRsZTogJ0ludmVudG9yeSBkYXRhJyxcbiAgICAgICAgICBkb2N1TGluazpcbiAgICAgICAgICAgICdodHRwczovL2RvY3VtZW50YXRpb24ud2F6dWguY29tL2N1cnJlbnQvdXNlci1tYW51YWwvcmVmZXJlbmNlL29zc2VjLWNvbmYvd29kbGUtc3lzY29sbGVjdG9yLmh0bWwnLFxuICAgICAgICAgIGRlc2M6XG4gICAgICAgICAgICAnR2F0aGVyIHJlbGV2YW50IGluZm9ybWF0aW9uIGFib3V0IHN5c3RlbSBPUywgaGFyZHdhcmUsIG5ldHdvcmtpbmcgYW5kIHBhY2thZ2VzJyxcbiAgICAgICAgICB3b2RsZTogW3sgbmFtZTogJ3N5c2NvbGxlY3RvcicgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnU3lzY29sbGVjdG9yIGludGVncmF0aW9uIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgJ3NjYW4tb24tc3RhcnQnOiAnU2NhbiBvbiBzdGFydCcsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnSW50ZXJ2YWwgYmV0d2VlbiBzeXN0ZW0gc2NhbnMnLFxuICAgICAgICAgICAgICBuZXR3b3JrOiAnU2NhbiBuZXR3b3JrIGludGVyZmFjZXMnLFxuICAgICAgICAgICAgICBvczogJ1NjYW4gb3BlcmF0aW5nIHN5c3RlbSBpbmZvJyxcbiAgICAgICAgICAgICAgaGFyZHdhcmU6ICdTY2FuIGhhcmR3YXJlIGluZm8nLFxuICAgICAgICAgICAgICBwYWNrYWdlczogJ1NjYW4gaW5zdGFsbGVkIHBhY2thZ2VzJyxcbiAgICAgICAgICAgICAgcG9ydHM6ICdTY2FuIGxpc3RlbmluZyBuZXR3b3JrIHBvcnRzJyxcbiAgICAgICAgICAgICAgcG9ydHNfYWxsOiAnU2NhbiBhbGwgbmV0d29yayBwb3J0cycsXG4gICAgICAgICAgICAgIHByb2Nlc3NlczogJ1NjYW4gY3VycmVudCBwcm9jZXNzZXMnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdBY3RpdmUgcmVzcG9uc2UnLFxuICAgICAgICAgIGRvY3VMaW5rOlxuICAgICAgICAgICAgJ2h0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20vY3VycmVudC91c2VyLW1hbnVhbC9yZWZlcmVuY2Uvb3NzZWMtY29uZi9hY3RpdmUtcmVzcG9uc2UuaHRtbCcsXG4gICAgICAgICAgZGVzYzogJ0FjdGl2ZSB0aHJlYXQgYWRkcmVzc2luZyBieSBpbW1lZGlhdGUgcmVzcG9uc2UnLFxuICAgICAgICAgIGNvbmZpZzogW3sgY29tcG9uZW50OiAnY29tJywgY29uZmlndXJhdGlvbjogJ2FjdGl2ZS1yZXNwb25zZScgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnQWN0aXZlIHJlc3BvbnNlIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgY2Ffc3RvcmU6ICdVc2UgdGhlIGZvbGxvd2luZyBsaXN0IG9mIHJvb3QgQ0EgY2VydGlmaWNhdGVzJyxcbiAgICAgICAgICAgICAgY2FfdmVyaWZpY2F0aW9uOiAnVmFsaWRhdGUgV1BLcyB1c2luZyByb290IENBIGNlcnRpZmljYXRlJ1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnQ29tbWFuZHMnLFxuICAgICAgICAgIGRvY3VMaW5rOlxuICAgICAgICAgICAgJ2h0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20vY3VycmVudC91c2VyLW1hbnVhbC9yZWZlcmVuY2Uvb3NzZWMtY29uZi93b2RsZS1jb21tYW5kLmh0bWwnLFxuICAgICAgICAgIGRlc2M6ICdDb25maWd1cmF0aW9uIG9wdGlvbnMgb2YgdGhlIENvbW1hbmQgd29kbGUnLFxuICAgICAgICAgIHdvZGxlOiBbeyBuYW1lOiAnY29tbWFuZCcgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnQ29tbWFuZCBkaXNhYmxlZCcsXG4gICAgICAgICAgICAgIHJ1bl9vbl9zdGFydDogJ1J1biBvbiBzdGFydCcsXG4gICAgICAgICAgICAgIGlnbm9yZV9vdXRwdXQ6ICdJZ25vcmUgY29tbWFuZCBvdXRwdXQnLFxuICAgICAgICAgICAgICBza2lwX3ZlcmlmaWNhdGlvbjogJ0lnbm9yZSBjaGVja3N1bSB2ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ0ludGVydmFsIGJldHdlZW4gZXhlY3V0aW9ucycsXG4gICAgICAgICAgICAgIHRhZzogJ0NvbW1hbmQgbmFtZScsXG4gICAgICAgICAgICAgIGNvbW1hbmQ6ICdDb21tYW5kIHRvIGV4ZWN1dGUnLFxuICAgICAgICAgICAgICB2ZXJpZnlfbWQ1OiAnVmVyaWZ5IE1ENSBzdW0nLFxuICAgICAgICAgICAgICB2ZXJpZnlfc2hhMTogJ1ZlcmlmeSBTSEExIHN1bScsXG4gICAgICAgICAgICAgIHZlcmlmeV9zaGEyNTY6ICdWZXJpZnkgU0hBMjU2IHN1bSdcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdWJ0aXRsZTogJ0RvY2tlciBsaXN0ZW5lcicsXG4gICAgICAgICAgZG9jdUxpbms6XG4gICAgICAgICAgICAnaHR0cHM6Ly9kb2N1bWVudGF0aW9uLndhenVoLmNvbS9jdXJyZW50L3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL3dvZGxlLWRvY2tlci5odG1sJyxcbiAgICAgICAgICBkZXNjOlxuICAgICAgICAgICAgJ01vbml0b3IgYW5kIGNvbGxlY3QgdGhlIGFjdGl2aXR5IGZyb20gRG9ja2VyIGNvbnRhaW5lcnMgc3VjaCBhcyBjcmVhdGlvbiwgcnVubmluZywgc3RhcnRpbmcsIHN0b3BwaW5nIG9yIHBhdXNpbmcgZXZlbnRzJyxcbiAgICAgICAgICB3b2RsZTogW3sgbmFtZTogJ2RvY2tlci1saXN0ZW5lcicgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnRG9ja2VyIGxpc3RlbmVyIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgcnVuX29uX3N0YXJ0OlxuICAgICAgICAgICAgICAgICdSdW4gdGhlIGxpc3RlbmVyIGltbWVkaWF0ZWx5IHdoZW4gc2VydmljZSBpcyBzdGFydGVkJyxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdXYWl0aW5nIHRpbWUgdG8gcmVydW4gdGhlIGxpc3RlbmVyIGluIGNhc2UgaXQgZmFpbHMnLFxuICAgICAgICAgICAgICBhdHRlbXB0czogJ051bWJlciBvZiBhdHRlbXB0cyB0byBleGVjdXRlIHRoZSBsaXN0ZW5lcidcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9LFxuICAgIHtcbiAgICAgIHRpdGxlOiAnTG9nIGRhdGEgYW5hbHlzaXMnLFxuICAgICAgc2VjdGlvbnM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnTG9nIGNvbGxlY3Rpb24nLFxuICAgICAgICAgIGRvY3VMaW5rOlxuICAgICAgICAgICAgJ2h0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20vY3VycmVudC91c2VyLW1hbnVhbC9jYXBhYmlsaXRpZXMvbG9nLWRhdGEtY29sbGVjdGlvbi9pbmRleC5odG1sJyxcbiAgICAgICAgICBkZXNjOlxuICAgICAgICAgICAgJ0xvZyBhbmFseXNpcyBmcm9tIHRleHQgZmlsZXMsIFdpbmRvd3MgZXZlbnRzIG9yIHN5c2xvZyBvdXRwdXRzJyxcbiAgICAgICAgICBjb25maWc6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgY29tcG9uZW50OiAnbG9nY29sbGVjdG9yJyxcbiAgICAgICAgICAgICAgY29uZmlndXJhdGlvbjogJ2xvY2FsZmlsZScsXG4gICAgICAgICAgICAgIGZpbHRlckJ5OiAnbG9nZm9ybWF0J1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHsgY29tcG9uZW50OiAnbG9nY29sbGVjdG9yJywgY29uZmlndXJhdGlvbjogJ3NvY2tldCcgfVxuICAgICAgICAgIF0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGxvZ2Zvcm1hdDogJ0xvZyBmb3JtYXQnLFxuICAgICAgICAgICAgICBsb2dfZm9ybWF0OiAnTG9nIGZvcm1hdCcsXG4gICAgICAgICAgICAgIGFsaWFzOiAnQ29tbWFuZCBhbGlhcycsXG4gICAgICAgICAgICAgIGlnbm9yZV9iaW5hcmllczogJ0lnbm9yZSBiaW5hcmllcycsXG4gICAgICAgICAgICAgIHRhcmdldDogJ1JlZGlyZWN0IG91dHB1dCB0byB0aGlzIHNvY2tldCcsXG4gICAgICAgICAgICAgIGZyZXF1ZW5jeTogJ0ludGVydmFsIGJldHdlZW4gY29tbWFuZCBleGVjdXRpb25zJyxcbiAgICAgICAgICAgICAgZmlsZTogJ0xvZyBsb2NhdGlvbicsXG4gICAgICAgICAgICAgIGxvY2F0aW9uOiAnTG9nIGxvY2F0aW9uJyxcbiAgICAgICAgICAgICAgc29ja2V0OiAnT3V0cHV0IHNvY2tldHMnLFxuICAgICAgICAgICAgICBzeXNsb2c6ICdTeXNsb2cnLFxuICAgICAgICAgICAgICBjb21tYW5kOiAnQ29tbWFuZCcsXG4gICAgICAgICAgICAgIGZ1bGxfY29tbWFuZDogJ0Z1bGwgY29tbWFuZCcsXG4gICAgICAgICAgICAgIGF1ZGl0OiAnQXVkaXQnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXSxcbiAgICAgICAgICBvcHRpb25zOiB7IGhpZGVIZWFkZXI6IHRydWUgfVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdJbnRlZ3JpdHkgbW9uaXRvcmluZycsXG4gICAgICAgICAgZG9jdUxpbms6XG4gICAgICAgICAgICAnaHR0cHM6Ly9kb2N1bWVudGF0aW9uLndhenVoLmNvbS9jdXJyZW50L3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL3N5c2NoZWNrLmh0bWwnLFxuICAgICAgICAgIGRlc2M6XG4gICAgICAgICAgICAnSWRlbnRpZnkgY2hhbmdlcyBpbiBjb250ZW50LCBwZXJtaXNzaW9ucywgb3duZXJzaGlwLCBhbmQgYXR0cmlidXRlcyBvZiBmaWxlcycsXG4gICAgICAgICAgY29uZmlnOiBbXG4gICAgICAgICAgICB7IGNvbXBvbmVudDogJ3N5c2NoZWNrJywgY29uZmlndXJhdGlvbjogJ3N5c2NoZWNrJywgbWF0cml4OiB0cnVlIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIHRhYnM6IFsnR2VuZXJhbCcsICdXaG8gZGF0YSddLFxuICAgICAgICAgIGxhYmVsczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBkaXNhYmxlZDogJ0ludGVncml0eSBtb25pdG9yaW5nIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgZnJlcXVlbmN5OiAnSW50ZXJ2YWwgKGluIHNlY29uZHMpIHRvIHJ1biB0aGUgaW50ZWdyaXR5IHNjYW4nLFxuICAgICAgICAgICAgICBza2lwX25mczogJ1NraXAgc2NhbiBvbiBDSUZTL05GUyBtb3VudHMnLFxuICAgICAgICAgICAgICBzY2FuX29uX3N0YXJ0OiAnU2NhbiBvbiBzdGFydCcsXG4gICAgICAgICAgICAgIGRpcmVjdG9yaWVzOiAnTW9uaXRvcmVkIGRpcmVjdG9yaWVzJyxcbiAgICAgICAgICAgICAgbm9kaWZmOiAnTm8gZGlmZiBkaXJlY3RvcmllcycsXG4gICAgICAgICAgICAgIGlnbm9yZTogJ0lnbm9yZWQgZmlsZXMgYW5kIGRpcmVjdG9yaWVzJyxcbiAgICAgICAgICAgICAgcmVzdGFydF9hdWRpdDogJ1Jlc3RhcnQgYXVkaXQnLFxuICAgICAgICAgICAgICBzdGFydHVwX2hlYWx0aGNoZWNrOiAnU3RhcnR1cCBoZWFsdGhjaGVjaydcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIG9wdHM6IHtcbiAgICAgICAgICAgIHJlYWx0aW1lOiAnUlQnLFxuICAgICAgICAgICAgY2hlY2tfd2hvZGF0YTogJ1dEJyxcbiAgICAgICAgICAgIHJlcG9ydF9jaGFuZ2VzOiAnQ2hhbmdlcycsXG4gICAgICAgICAgICBjaGVja19tZDVzdW06ICdNRDUnLFxuICAgICAgICAgICAgY2hlY2tfc2hhMXN1bTogJ1NIQTEnLFxuICAgICAgICAgICAgY2hlY2tfcGVybTogJ1Blci4nLFxuICAgICAgICAgICAgY2hlY2tfc2l6ZTogJ1NpemUnLFxuICAgICAgICAgICAgY2hlY2tfb3duZXI6ICdPd25lcicsXG4gICAgICAgICAgICBjaGVja19ncm91cDogJ0dyb3VwJyxcbiAgICAgICAgICAgIGNoZWNrX210aW1lOiAnTVQnLFxuICAgICAgICAgICAgY2hlY2tfaW5vZGU6ICdJbm9kZScsXG4gICAgICAgICAgICBjaGVja19zaGEyNTZzdW06ICdTSEEyNTYnLFxuICAgICAgICAgICAgZm9sbG93X3N5bWJvbGljX2xpbms6ICdTTCdcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9XG4gIF1cbn07XG4iXX0=