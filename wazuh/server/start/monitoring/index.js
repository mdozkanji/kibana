"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jobMonitoringRun = jobMonitoringRun;

var _nodeCron = _interopRequireDefault(require("node-cron"));

var _logger = require("../../lib/logger");

var _monitoringTemplate = require("../../integration-files/monitoring-template");

var _getConfiguration = require("../../lib/get-configuration");

var _parseCron = require("../../lib/parse-cron");

var _indexDate = require("../../lib/index-date");

var _buildIndexSettings = require("../../lib/build-index-settings");

var _wazuhHosts = require("../../controllers/wazuh-hosts");

var _constants = require("../../../common/constants");

var _tryCatchForIndexPermissionError = require("../tryCatchForIndexPermissionError");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/*
 * Wazuh app - Module for agent info fetching functions
 * Copyright (C) 2015-2021 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const blueWazuh = '\u001b[34mwazuh\u001b[39m';
const monitoringErrorLogColors = [blueWazuh, 'monitoring', 'error'];
const wazuhHostController = new _wazuhHosts.WazuhHostsCtrl();
let MONITORING_ENABLED, MONITORING_FREQUENCY, MONITORING_CRON_FREQ, MONITORING_CREATION, MONITORING_INDEX_PATTERN, MONITORING_INDEX_PREFIX; // Utils functions

/**
 * Delay as promise
 * @param timeMs
 */

function delay(timeMs) {
  return new Promise(resolve => {
    setTimeout(resolve, timeMs);
  });
}
/**
 * Get the setting value from the configuration
 * @param setting
 * @param configuration
 * @param defaultValue
 */


function getAppConfigurationSetting(setting, configuration, defaultValue) {
  return typeof configuration[setting] !== 'undefined' ? configuration[setting] : defaultValue;
}

;
/**
 * Set the monitoring variables
 * @param context
 */

function initMonitoringConfiguration(context) {
  try {
    const appConfig = (0, _getConfiguration.getConfiguration)();
    MONITORING_ENABLED = appConfig && typeof appConfig['wazuh.monitoring.enabled'] !== 'undefined' ? appConfig['wazuh.monitoring.enabled'] && appConfig['wazuh.monitoring.enabled'] !== 'worker' : _constants.WAZUH_MONITORING_DEFAULT_ENABLED;
    MONITORING_FREQUENCY = getAppConfigurationSetting('wazuh.monitoring.frequency', appConfig, _constants.WAZUH_MONITORING_DEFAULT_FREQUENCY);
    MONITORING_CRON_FREQ = (0, _parseCron.parseCron)(MONITORING_FREQUENCY);
    MONITORING_CREATION = getAppConfigurationSetting('wazuh.monitoring.creation', appConfig, _constants.WAZUH_MONITORING_DEFAULT_CREATION);
    MONITORING_INDEX_PATTERN = getAppConfigurationSetting('wazuh.monitoring.pattern', appConfig, _constants.WAZUH_MONITORING_PATTERN);
    const lastCharIndexPattern = MONITORING_INDEX_PATTERN[MONITORING_INDEX_PATTERN.length - 1];

    if (lastCharIndexPattern !== '*') {
      MONITORING_INDEX_PATTERN += '*';
    }

    ;
    MONITORING_INDEX_PREFIX = MONITORING_INDEX_PATTERN.slice(0, MONITORING_INDEX_PATTERN.length - 1);
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.enabled: ${MONITORING_ENABLED}`, 'debug');
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.frequency: ${MONITORING_FREQUENCY} (${MONITORING_CRON_FREQ})`, 'debug');
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.pattern: ${MONITORING_INDEX_PATTERN} (index prefix: ${MONITORING_INDEX_PREFIX})`, 'debug');
  } catch (error) {
    const errorMessage = error.message || error;
    (0, _logger.log)('monitoring:initMonitoringConfiguration', errorMessage);
    context.wazuh.logger.error(errorMessage);
  }
}

;
/**
 * Main. First execution when installing / loading App.
 * @param context
 */

async function init(context) {
  try {
    if (MONITORING_ENABLED) {
      await checkTemplate(context);
    }

    ;
  } catch (error) {
    const errorMessage = error.message || error;
    (0, _logger.log)('monitoring:init', error.message || error);
    context.wazuh.logger.error(errorMessage);
  }
}
/**
 * Verify wazuh-agent template
 */


async function checkTemplate(context) {
  try {
    (0, _logger.log)('monitoring:checkTemplate', 'Updating the monitoring template', 'debug');

    try {
      // Check if the template already exists
      const currentTemplate = await context.core.elasticsearch.client.asInternalUser.indices.getTemplate({
        name: _constants.WAZUH_MONITORING_TEMPLATE_NAME
      }); // Copy already created index patterns

      _monitoringTemplate.monitoringTemplate.index_patterns = currentTemplate.body[_constants.WAZUH_MONITORING_TEMPLATE_NAME].index_patterns;
    } catch (error) {
      // Init with the default index pattern
      _monitoringTemplate.monitoringTemplate.index_patterns = [_constants.WAZUH_MONITORING_PATTERN];
    } // Check if the user is using a custom pattern and add it to the template if it does


    if (!_monitoringTemplate.monitoringTemplate.index_patterns.includes(MONITORING_INDEX_PATTERN)) {
      _monitoringTemplate.monitoringTemplate.index_patterns.push(MONITORING_INDEX_PATTERN);
    }

    ; // Update the monitoring template

    await context.core.elasticsearch.client.asInternalUser.indices.putTemplate({
      name: _constants.WAZUH_MONITORING_TEMPLATE_NAME,
      body: _monitoringTemplate.monitoringTemplate
    });
    (0, _logger.log)('monitoring:checkTemplate', 'Updated the monitoring template', 'debug');
  } catch (error) {
    const errorMessage = `Something went wrong updating the monitoring template ${error.message || error}`;
    (0, _logger.log)('monitoring:checkTemplate', errorMessage);
    context.wazuh.logger.error(monitoringErrorLogColors, errorMessage);
    throw error;
  }
}
/**
 * Save agent status into elasticsearch, create index and/or insert document
 * @param {*} context
 * @param {*} data
 */


async function insertMonitoringDataElasticsearch(context, data) {
  const monitoringIndexName = MONITORING_INDEX_PREFIX + (0, _indexDate.indexDate)(MONITORING_CREATION);

  if (!MONITORING_ENABLED) {
    return;
  }

  ;

  try {
    await (0, _tryCatchForIndexPermissionError.tryCatchForIndexPermissionError)(monitoringIndexName)(async () => {
      const exists = await context.core.elasticsearch.client.asInternalUser.indices.exists({
        index: monitoringIndexName
      });

      if (!exists.body) {
        await createIndex(context, monitoringIndexName);
      }

      ; // Update the index configuration

      const appConfig = (0, _getConfiguration.getConfiguration)();
      const indexConfiguration = (0, _buildIndexSettings.buildIndexSettings)(appConfig, 'wazuh.monitoring', _constants.WAZUH_MONITORING_DEFAULT_INDICES_SHARDS); // To update the index settings with this client is required close the index, update the settings and open it
      // Number of shards is not dynamic so delete that setting if it's given

      delete indexConfiguration.settings.index.number_of_shards;
      await context.core.elasticsearch.client.asInternalUser.indices.putSettings({
        index: monitoringIndexName,
        body: indexConfiguration
      }); // Insert data to the monitoring index

      await insertDataToIndex(context, monitoringIndexName, data);
    })();
  } catch (error) {
    (0, _logger.log)('monitoring:insertMonitoringDataElasticsearch', error.message || error);
    context.wazuh.logger.error(error.message);
  }
}
/**
 * Inserting one document per agent into Elastic. Bulk.
 * @param {*} context Endpoint
 * @param {String} indexName The name for the index (e.g. daily: wazuh-monitoring-YYYY.MM.DD)
 * @param {*} data
 */


async function insertDataToIndex(context, indexName, data) {
  const {
    agents,
    apiHost
  } = data;

  try {
    if (agents.length > 0) {
      (0, _logger.log)('monitoring:insertDataToIndex', `Bulk data to index ${indexName} for ${agents.length} agents`, 'debug');
      const bodyBulk = agents.map(agent => {
        const agentInfo = { ...agent
        };
        agentInfo['timestamp'] = new Date(Date.now()).toISOString();
        agentInfo.host = agent.manager;
        agentInfo.cluster = {
          name: apiHost.clusterName ? apiHost.clusterName : 'disabled'
        };
        return `{ "index":  { "_index": "${indexName}" } }\n${JSON.stringify(agentInfo)}\n`;
      }).join('');
      await context.core.elasticsearch.client.asInternalUser.bulk({
        index: indexName,
        body: bodyBulk
      });
      (0, _logger.log)('monitoring:insertDataToIndex', `Bulk data to index ${indexName} for ${agents.length} agents completed`, 'debug');
    }
  } catch (error) {
    (0, _logger.log)('monitoring:insertDataToIndex', `Error inserting agent data into elasticsearch. Bulk request failed due to ${error.message || error}`);
  }
}
/**
 * Create the wazuh-monitoring index
 * @param {*} context context
 * @param {String} indexName The name for the index (e.g. daily: wazuh-monitoring-YYYY.MM.DD)
 */


async function createIndex(context, indexName) {
  try {
    if (!MONITORING_ENABLED) return;
    const appConfig = (0, _getConfiguration.getConfiguration)();
    const IndexConfiguration = {
      settings: {
        index: {
          number_of_shards: getAppConfigurationSetting('wazuh.monitoring.shards', appConfig, _constants.WAZUH_INDEX_SHARDS),
          number_of_replicas: getAppConfigurationSetting('wazuh.monitoring.replicas', appConfig, _constants.WAZUH_INDEX_REPLICAS)
        }
      }
    };
    await context.core.elasticsearch.client.asInternalUser.indices.create({
      index: indexName,
      body: IndexConfiguration
    });
    (0, _logger.log)('monitoring:createIndex', `Successfully created new index: ${indexName}`, 'debug');
  } catch (error) {
    const errorMessage = `Could not create ${indexName} index on elasticsearch due to ${error.message || error}`;
    (0, _logger.log)('monitoring:createIndex', errorMessage);
    context.wazuh.logger.error(errorMessage);
  }
}
/**
* Wait until Kibana server is ready
*/


async function checkKibanaStatus(context) {
  try {
    (0, _logger.log)('monitoring:checkKibanaStatus', 'Waiting for Kibana and Elasticsearch servers to be ready...', 'debug');
    await checkElasticsearchServer(context);
    await init(context);
    return;
  } catch (error) {
    (0, _logger.log)('monitoring:checkKibanaStatus', error.mesage || error);

    try {
      await delay(3000);
      await checkKibanaStatus(context);
    } catch (error) {}

    ;
  }
}
/**
 * Check Elasticsearch Server status and Kibana index presence
 */


async function checkElasticsearchServer(context) {
  try {
    const data = await context.core.elasticsearch.client.asInternalUser.indices.exists({
      index: context.server.config.kibana.index
    });
    return data.body; // TODO: check if Elasticsearch can receive requests
    // if (data) {
    //   const pluginsData = await this.server.plugins.elasticsearch.waitUntilReady();
    //   return pluginsData;
    // }

    return Promise.reject(data);
  } catch (error) {
    (0, _logger.log)('monitoring:checkElasticsearchServer', error.message || error);
    return Promise.reject(error);
  }
}

const fakeResponseEndpoint = {
  ok: body => body,
  custom: body => body
};
/**
 * Get API configuration from elastic and callback to loadCredentials
 */

async function getHostsConfiguration() {
  try {
    const hosts = await wazuhHostController.getHostsEntries(false, false, fakeResponseEndpoint);

    if (hosts.body.length) {
      return hosts.body;
    }

    ;
    (0, _logger.log)('monitoring:getConfig', 'There are no Wazuh API entries yet', 'debug');
    return Promise.reject({
      error: 'no credentials',
      error_code: 1
    });
  } catch (error) {
    (0, _logger.log)('monitoring:getHostsConfiguration', error.message || error);
    return Promise.reject({
      error: 'no wazuh hosts',
      error_code: 2
    });
  }
}
/**
   * Task used by the cron job.
   */


async function cronTask(context) {
  try {
    const templateMonitoring = await context.core.elasticsearch.client.asInternalUser.indices.getTemplate({
      name: _constants.WAZUH_MONITORING_TEMPLATE_NAME
    });
    const apiHosts = await getHostsConfiguration();
    const apiHostsUnique = (apiHosts || []).filter((apiHost, index, self) => index === self.findIndex(t => t.user === apiHost.user && t.password === apiHost.password && t.url === apiHost.url && t.port === apiHost.port));

    for (let apiHost of apiHostsUnique) {
      try {
        const {
          agents,
          apiHost: host
        } = await getApiInfo(context, apiHost);
        await insertMonitoringDataElasticsearch(context, {
          agents,
          apiHost: host
        });
      } catch (error) {}

      ;
    }
  } catch (error) {
    // Retry to call itself again if Kibana index is not ready yet
    // try {
    //   if (
    //     this.wzWrapper.buildingKibanaIndex ||
    //     ((error || {}).status === 404 &&
    //       (error || {}).displayName === 'NotFound')
    //   ) {
    //     await delay(1000);
    //     return cronTask(context);
    //   }
    // } catch (error) {} //eslint-disable-line
    (0, _logger.log)('monitoring:cronTask', error.message || error);
    context.wazuh.logger.error(error.message || error);
  }
}
/**
 * Get API and agents info
 * @param context
 * @param apiHost
 */


async function getApiInfo(context, apiHost) {
  try {
    (0, _logger.log)('monitoring:getApiInfo', `Getting API info for ${apiHost.id}`, 'debug');
    const responseIsCluster = await context.wazuh.api.client.asInternalUser.request('GET', '/cluster/status', {}, {
      apiHostID: apiHost.id
    });
    const isCluster = (((responseIsCluster || {}).data || {}).data || {}).enabled === 'yes';

    if (isCluster) {
      const responseClusterInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/local/info`, {}, {
        apiHostID: apiHost.id
      });
      apiHost.clusterName = responseClusterInfo.data.data.affected_items[0].cluster;
    }

    ;
    const agents = await fetchAllAgentsFromApiHost(context, apiHost);
    return {
      agents,
      apiHost
    };
  } catch (error) {
    (0, _logger.log)('monitoring:getApiInfo', error.message || error);
    throw error;
  }
}

;
/**
 * Fetch all agents for the API provided
 * @param context
 * @param apiHost
 */

async function fetchAllAgentsFromApiHost(context, apiHost) {
  let agents = [];

  try {
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `Getting all agents from ApiID: ${apiHost.id}`, 'debug');
    const responseAgentsCount = await context.wazuh.api.client.asInternalUser.request('GET', '/agents', {
      params: {
        offset: 0,
        limit: 1,
        q: 'id!=000'
      }
    }, {
      apiHostID: apiHost.id
    });
    const agentsCount = responseAgentsCount.data.data.total_affected_items;
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}, Agent count: ${agentsCount}`, 'debug');
    let payload = {
      offset: 0,
      limit: 500,
      q: 'id!=000'
    };

    while (agents.length < agentsCount && payload.offset < agentsCount) {
      try {
        const responseAgents = await context.wazuh.api.client.asInternalUser.request('GET', `/agents`, {
          params: payload
        }, {
          apiHostID: apiHost.id
        });
        agents = [...agents, ...responseAgents.data.data.affected_items];
        payload.offset += payload.limit;
      } catch (error) {
        (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}, Error request with offset/limit ${payload.offset}/${payload.limit}: ${error.message || error}`);
      }
    }

    return agents;
  } catch (error) {
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}. Error: ${error.message || error}`);
    throw error;
  }
}

;
/**
 * Start the cron job
 */

async function jobMonitoringRun(context) {
  // Init the monitoring variables
  initMonitoringConfiguration(context); // Check Kibana index and if it is prepared, start the initialization of Wazuh App.

  await checkKibanaStatus(context); // // Run the cron job only it it's enabled

  if (MONITORING_ENABLED) {
    cronTask(context);

    _nodeCron.default.schedule(MONITORING_CRON_FREQ, () => cronTask(context));
  }
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbImJsdWVXYXp1aCIsIm1vbml0b3JpbmdFcnJvckxvZ0NvbG9ycyIsIndhenVoSG9zdENvbnRyb2xsZXIiLCJXYXp1aEhvc3RzQ3RybCIsIk1PTklUT1JJTkdfRU5BQkxFRCIsIk1PTklUT1JJTkdfRlJFUVVFTkNZIiwiTU9OSVRPUklOR19DUk9OX0ZSRVEiLCJNT05JVE9SSU5HX0NSRUFUSU9OIiwiTU9OSVRPUklOR19JTkRFWF9QQVRURVJOIiwiTU9OSVRPUklOR19JTkRFWF9QUkVGSVgiLCJkZWxheSIsInRpbWVNcyIsIlByb21pc2UiLCJyZXNvbHZlIiwic2V0VGltZW91dCIsImdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nIiwic2V0dGluZyIsImNvbmZpZ3VyYXRpb24iLCJkZWZhdWx0VmFsdWUiLCJpbml0TW9uaXRvcmluZ0NvbmZpZ3VyYXRpb24iLCJjb250ZXh0IiwiYXBwQ29uZmlnIiwiV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0VOQUJMRUQiLCJXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfRlJFUVVFTkNZIiwiV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0NSRUFUSU9OIiwiV0FaVUhfTU9OSVRPUklOR19QQVRURVJOIiwibGFzdENoYXJJbmRleFBhdHRlcm4iLCJsZW5ndGgiLCJzbGljZSIsImVycm9yIiwiZXJyb3JNZXNzYWdlIiwibWVzc2FnZSIsIndhenVoIiwibG9nZ2VyIiwiaW5pdCIsImNoZWNrVGVtcGxhdGUiLCJjdXJyZW50VGVtcGxhdGUiLCJjb3JlIiwiZWxhc3RpY3NlYXJjaCIsImNsaWVudCIsImFzSW50ZXJuYWxVc2VyIiwiaW5kaWNlcyIsImdldFRlbXBsYXRlIiwibmFtZSIsIldBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRSIsIm1vbml0b3JpbmdUZW1wbGF0ZSIsImluZGV4X3BhdHRlcm5zIiwiYm9keSIsImluY2x1ZGVzIiwicHVzaCIsInB1dFRlbXBsYXRlIiwiaW5zZXJ0TW9uaXRvcmluZ0RhdGFFbGFzdGljc2VhcmNoIiwiZGF0YSIsIm1vbml0b3JpbmdJbmRleE5hbWUiLCJleGlzdHMiLCJpbmRleCIsImNyZWF0ZUluZGV4IiwiaW5kZXhDb25maWd1cmF0aW9uIiwiV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0lORElDRVNfU0hBUkRTIiwic2V0dGluZ3MiLCJudW1iZXJfb2Zfc2hhcmRzIiwicHV0U2V0dGluZ3MiLCJpbnNlcnREYXRhVG9JbmRleCIsImluZGV4TmFtZSIsImFnZW50cyIsImFwaUhvc3QiLCJib2R5QnVsayIsIm1hcCIsImFnZW50IiwiYWdlbnRJbmZvIiwiRGF0ZSIsIm5vdyIsInRvSVNPU3RyaW5nIiwiaG9zdCIsIm1hbmFnZXIiLCJjbHVzdGVyIiwiY2x1c3Rlck5hbWUiLCJKU09OIiwic3RyaW5naWZ5Iiwiam9pbiIsImJ1bGsiLCJJbmRleENvbmZpZ3VyYXRpb24iLCJXQVpVSF9JTkRFWF9TSEFSRFMiLCJudW1iZXJfb2ZfcmVwbGljYXMiLCJXQVpVSF9JTkRFWF9SRVBMSUNBUyIsImNyZWF0ZSIsImNoZWNrS2liYW5hU3RhdHVzIiwiY2hlY2tFbGFzdGljc2VhcmNoU2VydmVyIiwibWVzYWdlIiwic2VydmVyIiwiY29uZmlnIiwia2liYW5hIiwicmVqZWN0IiwiZmFrZVJlc3BvbnNlRW5kcG9pbnQiLCJvayIsImN1c3RvbSIsImdldEhvc3RzQ29uZmlndXJhdGlvbiIsImhvc3RzIiwiZ2V0SG9zdHNFbnRyaWVzIiwiZXJyb3JfY29kZSIsImNyb25UYXNrIiwidGVtcGxhdGVNb25pdG9yaW5nIiwiYXBpSG9zdHMiLCJhcGlIb3N0c1VuaXF1ZSIsImZpbHRlciIsInNlbGYiLCJmaW5kSW5kZXgiLCJ0IiwidXNlciIsInBhc3N3b3JkIiwidXJsIiwicG9ydCIsImdldEFwaUluZm8iLCJpZCIsInJlc3BvbnNlSXNDbHVzdGVyIiwiYXBpIiwicmVxdWVzdCIsImFwaUhvc3RJRCIsImlzQ2x1c3RlciIsImVuYWJsZWQiLCJyZXNwb25zZUNsdXN0ZXJJbmZvIiwiYWZmZWN0ZWRfaXRlbXMiLCJmZXRjaEFsbEFnZW50c0Zyb21BcGlIb3N0IiwicmVzcG9uc2VBZ2VudHNDb3VudCIsInBhcmFtcyIsIm9mZnNldCIsImxpbWl0IiwicSIsImFnZW50c0NvdW50IiwidG90YWxfYWZmZWN0ZWRfaXRlbXMiLCJwYXlsb2FkIiwicmVzcG9uc2VBZ2VudHMiLCJqb2JNb25pdG9yaW5nUnVuIiwiY3JvbiIsInNjaGVkdWxlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBV0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBVUE7Ozs7QUE3QkE7Ozs7Ozs7Ozs7O0FBK0JBLE1BQU1BLFNBQVMsR0FBRywyQkFBbEI7QUFDQSxNQUFNQyx3QkFBd0IsR0FBRyxDQUFDRCxTQUFELEVBQVksWUFBWixFQUEwQixPQUExQixDQUFqQztBQUNBLE1BQU1FLG1CQUFtQixHQUFHLElBQUlDLDBCQUFKLEVBQTVCO0FBRUEsSUFBSUMsa0JBQUosRUFBd0JDLG9CQUF4QixFQUE4Q0Msb0JBQTlDLEVBQW9FQyxtQkFBcEUsRUFBeUZDLHdCQUF6RixFQUFtSEMsdUJBQW5ILEMsQ0FFQTs7QUFFQTs7Ozs7QUFJQSxTQUFTQyxLQUFULENBQWVDLE1BQWYsRUFBK0I7QUFDN0IsU0FBTyxJQUFJQyxPQUFKLENBQWFDLE9BQUQsSUFBYTtBQUM5QkMsSUFBQUEsVUFBVSxDQUFDRCxPQUFELEVBQVVGLE1BQVYsQ0FBVjtBQUNELEdBRk0sQ0FBUDtBQUdEO0FBRUQ7Ozs7Ozs7O0FBTUEsU0FBU0ksMEJBQVQsQ0FBb0NDLE9BQXBDLEVBQXFEQyxhQUFyRCxFQUF5RUMsWUFBekUsRUFBMkY7QUFDekYsU0FBTyxPQUFPRCxhQUFhLENBQUNELE9BQUQsQ0FBcEIsS0FBa0MsV0FBbEMsR0FBZ0RDLGFBQWEsQ0FBQ0QsT0FBRCxDQUE3RCxHQUF5RUUsWUFBaEY7QUFDRDs7QUFBQTtBQUVEOzs7OztBQUlBLFNBQVNDLDJCQUFULENBQXFDQyxPQUFyQyxFQUE2QztBQUMz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O0FBQzlDO0FBQ0FELEVBQUFBLDJCQUEyQixDQUFDQyxPQUFELENBQTNCLENBRjhDLENBRzlDOztBQUNBLFFBQU1rRSxpQkFBaUIsQ0FBQ2xFLE9BQUQsQ0FBdkIsQ0FKOEMsQ0FLOUM7O0FBQ0EsTUFBSWhCLGtCQUFKLEVBQXdCO0FBQ3RCZ0csSUFBQUEsUUFBUSxDQUFDaEYsT0FBRCxDQUFSOztBQUNBaUgsc0JBQUtDLFFBQUwsQ0FBY2hJLG9CQUFkLEVBQW9DLE1BQU04RixRQUFRLENBQUNoRixPQUFELENBQWxEO0FBQ0Q7QUFDRiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgZm9yIGFnZW50IGluZm8gZmV0Y2hpbmcgZnVuY3Rpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMSBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IGNyb24gZnJvbSAnbm9kZS1jcm9uJztcbmltcG9ydCB7IGxvZyB9IGZyb20gJy4uLy4uL2xpYi9sb2dnZXInO1xuaW1wb3J0IHsgbW9uaXRvcmluZ1RlbXBsYXRlIH0gZnJvbSAnLi4vLi4vaW50ZWdyYXRpb24tZmlsZXMvbW9uaXRvcmluZy10ZW1wbGF0ZSc7XG5pbXBvcnQgeyBnZXRDb25maWd1cmF0aW9uIH0gZnJvbSAnLi4vLi4vbGliL2dldC1jb25maWd1cmF0aW9uJztcbmltcG9ydCB7IHBhcnNlQ3JvbiB9IGZyb20gJy4uLy4uL2xpYi9wYXJzZS1jcm9uJztcbmltcG9ydCB7IGluZGV4RGF0ZSB9IGZyb20gJy4uLy4uL2xpYi9pbmRleC1kYXRlJztcbmltcG9ydCB7IGJ1aWxkSW5kZXhTZXR0aW5ncyB9IGZyb20gJy4uLy4uL2xpYi9idWlsZC1pbmRleC1zZXR0aW5ncyc7XG5pbXBvcnQgeyBXYXp1aEhvc3RzQ3RybCB9IGZyb20gJy4uLy4uL2NvbnRyb2xsZXJzL3dhenVoLWhvc3RzJztcbmltcG9ydCB7IFxuICBXQVpVSF9NT05JVE9SSU5HX1BBVFRFUk4sXG4gIFdBWlVIX0lOREVYX1NIQVJEUyxcbiAgV0FaVUhfSU5ERVhfUkVQTElDQVMsXG4gIFdBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRSxcbiAgV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0lORElDRVNfU0hBUkRTLFxuICBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfQ1JFQVRJT04sXG4gIFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9FTkFCTEVELFxuICBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfRlJFUVVFTkNZLFxufSBmcm9tICcuLi8uLi8uLi9jb21tb24vY29uc3RhbnRzJztcbmltcG9ydCB7IHRyeUNhdGNoRm9ySW5kZXhQZXJtaXNzaW9uRXJyb3IgfSBmcm9tICcuLi90cnlDYXRjaEZvckluZGV4UGVybWlzc2lvbkVycm9yJztcblxuY29uc3QgYmx1ZVdhenVoID0gJ1xcdTAwMWJbMzRtd2F6dWhcXHUwMDFiWzM5bSc7XG5jb25zdCBtb25pdG9yaW5nRXJyb3JMb2dDb2xvcnMgPSBbYmx1ZVdhenVoLCAnbW9uaXRvcmluZycsICdlcnJvciddO1xuY29uc3Qgd2F6dWhIb3N0Q29udHJvbGxlciA9IG5ldyBXYXp1aEhvc3RzQ3RybCgpO1xuXG5sZXQgTU9OSVRPUklOR19FTkFCTEVELCBNT05JVE9SSU5HX0ZSRVFVRU5DWSwgTU9OSVRPUklOR19DUk9OX0ZSRVEsIE1PTklUT1JJTkdfQ1JFQVRJT04sIE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTiwgTU9OSVRPUklOR19JTkRFWF9QUkVGSVg7XG5cbi8vIFV0aWxzIGZ1bmN0aW9uc1xuXG4vKipcbiAqIERlbGF5IGFzIHByb21pc2VcbiAqIEBwYXJhbSB0aW1lTXNcbiAqL1xuZnVuY3Rpb24gZGVsYXkodGltZU1zOiBudW1iZXIpIHtcbiAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7XG4gICAgc2V0VGltZW91dChyZXNvbHZlLCB0aW1lTXMpO1xuICB9KTtcbn1cblxuLyoqXG4gKiBHZXQgdGhlIHNldHRpbmcgdmFsdWUgZnJvbSB0aGUgY29uZmlndXJhdGlvblxuICogQHBhcmFtIHNldHRpbmdcbiAqIEBwYXJhbSBjb25maWd1cmF0aW9uXG4gKiBAcGFyYW0gZGVmYXVsdFZhbHVlXG4gKi9cbmZ1bmN0aW9uIGdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nKHNldHRpbmc6IHN0cmluZywgY29uZmlndXJhdGlvbjogYW55LCBkZWZhdWx0VmFsdWU6IGFueSl7XG4gIHJldHVybiB0eXBlb2YgY29uZmlndXJhdGlvbltzZXR0aW5nXSAhPT0gJ3VuZGVmaW5lZCcgPyBjb25maWd1cmF0aW9uW3NldHRpbmddIDogZGVmYXVsdFZhbHVlO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIG1vbml0b3JpbmcgdmFyaWFibGVzXG4gKiBAcGFyYW0gY29udGV4dFxuICovXG5mdW5jdGlvbiBpbml0TW9uaXRvcmluZ0NvbmZpZ3VyYXRpb24oY29udGV4dCl7XG4gIHRyeXtcbiAgICBjb25zdCBhcHBDb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgTU9OSVRPUklOR19FTkFCTEVEID0gYXBwQ29uZmlnICYmIHR5cGVvZiBhcHBDb25maWdbJ3dhenVoLm1vbml0b3JpbmcuZW5hYmxlZCddICE9PSAndW5kZWZpbmVkJ1xuICAgICAgPyBhcHBDb25maWdbJ3dhenVoLm1vbml0b3JpbmcuZW5hYmxlZCddICYmXG4gICAgICAgIGFwcENvbmZpZ1snd2F6dWgubW9uaXRvcmluZy5lbmFibGVkJ10gIT09ICd3b3JrZXInXG4gICAgICA6IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9FTkFCTEVEO1xuICAgIE1PTklUT1JJTkdfRlJFUVVFTkNZID0gZ2V0QXBwQ29uZmlndXJhdGlvblNldHRpbmcoJ3dhenVoLm1vbml0b3JpbmcuZnJlcXVlbmN5JywgYXBwQ29uZmlnLCBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfRlJFUVVFTkNZKTtcbiAgICBNT05JVE9SSU5HX0NST05fRlJFUSA9IHBhcnNlQ3JvbihNT05JVE9SSU5HX0ZSRVFVRU5DWSk7XG4gICAgTU9OSVRPUklOR19DUkVBVElPTiA9IGdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nKCd3YXp1aC5tb25pdG9yaW5nLmNyZWF0aW9uJywgYXBwQ29uZmlnLCBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfQ1JFQVRJT04pO1xuXG4gICAgTU9OSVRPUklOR19JTkRFWF9QQVRURVJOID0gZ2V0QXBwQ29uZmlndXJhdGlvblNldHRpbmcoJ3dhenVoLm1vbml0b3JpbmcucGF0dGVybicsIGFwcENvbmZpZywgV0FaVUhfTU9OSVRPUklOR19QQVRURVJOKTtcbiAgICBjb25zdCBsYXN0Q2hhckluZGV4UGF0dGVybiA9IE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTltNT05JVE9SSU5HX0lOREVYX1BBVFRFUk4ubGVuZ3RoIC0gMV07XG4gICAgaWYgKGxhc3RDaGFySW5kZXhQYXR0ZXJuICE9PSAnKicpIHtcbiAgICAgIE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTiArPSAnKic7XG4gICAgfTtcbiAgICBNT05JVE9SSU5HX0lOREVYX1BSRUZJWCA9IE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTi5zbGljZSgwLE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTi5sZW5ndGggLSAxKTtcblxuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmluaXRNb25pdG9yaW5nQ29uZmlndXJhdGlvbicsXG4gICAgICBgd2F6dWgubW9uaXRvcmluZy5lbmFibGVkOiAke01PTklUT1JJTkdfRU5BQkxFRH1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzppbml0TW9uaXRvcmluZ0NvbmZpZ3VyYXRpb24nLFxuICAgICAgYHdhenVoLm1vbml0b3JpbmcuZnJlcXVlbmN5OiAke01PTklUT1JJTkdfRlJFUVVFTkNZfSAoJHtNT05JVE9SSU5HX0NST05fRlJFUX0pYCxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuXG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6aW5pdE1vbml0b3JpbmdDb25maWd1cmF0aW9uJyxcbiAgICAgIGB3YXp1aC5tb25pdG9yaW5nLnBhdHRlcm46ICR7TU9OSVRPUklOR19JTkRFWF9QQVRURVJOfSAoaW5kZXggcHJlZml4OiAke01PTklUT1JJTkdfSU5ERVhfUFJFRklYfSlgLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gIH1jYXRjaChlcnJvcil7XG4gICAgY29uc3QgZXJyb3JNZXNzYWdlID0gZXJyb3IubWVzc2FnZSB8fCBlcnJvcjtcbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzppbml0TW9uaXRvcmluZ0NvbmZpZ3VyYXRpb24nLFxuICAgICAgZXJyb3JNZXNzYWdlXG4gICAgKTtcbiAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihlcnJvck1lc3NhZ2UpXG4gIH1cbn07XG5cbi8qKlxuICogTWFpbi4gRmlyc3QgZXhlY3V0aW9uIHdoZW4gaW5zdGFsbGluZyAvIGxvYWRpbmcgQXBwLlxuICogQHBhcmFtIGNvbnRleHRcbiAqL1xuYXN5bmMgZnVuY3Rpb24gaW5pdChjb250ZXh0KSB7XG4gIHRyeSB7XG4gICAgaWYgKE1PTklUT1JJTkdfRU5BQkxFRCkge1xuICAgICAgYXdhaXQgY2hlY2tUZW1wbGF0ZShjb250ZXh0KTtcbiAgICB9O1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9IGVycm9yLm1lc3NhZ2UgfHwgZXJyb3I7XG4gICAgbG9nKCdtb25pdG9yaW5nOmluaXQnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihlcnJvck1lc3NhZ2UpO1xuICB9XG59XG5cbi8qKlxuICogVmVyaWZ5IHdhenVoLWFnZW50IHRlbXBsYXRlXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGNoZWNrVGVtcGxhdGUoY29udGV4dCkge1xuICB0cnkge1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrVGVtcGxhdGUnLFxuICAgICAgJ1VwZGF0aW5nIHRoZSBtb25pdG9yaW5nIHRlbXBsYXRlJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIENoZWNrIGlmIHRoZSB0ZW1wbGF0ZSBhbHJlYWR5IGV4aXN0c1xuICAgICAgY29uc3QgY3VycmVudFRlbXBsYXRlID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZ2V0VGVtcGxhdGUoe1xuICAgICAgICBuYW1lOiBXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUVcbiAgICAgIH0pO1xuICAgICAgLy8gQ29weSBhbHJlYWR5IGNyZWF0ZWQgaW5kZXggcGF0dGVybnNcbiAgICAgIG1vbml0b3JpbmdUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucyA9IGN1cnJlbnRUZW1wbGF0ZS5ib2R5W1dBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRV0uaW5kZXhfcGF0dGVybnM7XG4gICAgfWNhdGNoIChlcnJvcikge1xuICAgICAgLy8gSW5pdCB3aXRoIHRoZSBkZWZhdWx0IGluZGV4IHBhdHRlcm5cbiAgICAgIG1vbml0b3JpbmdUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucyA9IFtXQVpVSF9NT05JVE9SSU5HX1BBVFRFUk5dO1xuICAgIH1cblxuICAgIC8vIENoZWNrIGlmIHRoZSB1c2VyIGlzIHVzaW5nIGEgY3VzdG9tIHBhdHRlcm4gYW5kIGFkZCBpdCB0byB0aGUgdGVtcGxhdGUgaWYgaXQgZG9lc1xuICAgIGlmICghbW9uaXRvcmluZ1RlbXBsYXRlLmluZGV4X3BhdHRlcm5zLmluY2x1ZGVzKE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTikpIHtcbiAgICAgIG1vbml0b3JpbmdUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucy5wdXNoKE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTik7XG4gICAgfTtcblxuICAgIC8vIFVwZGF0ZSB0aGUgbW9uaXRvcmluZyB0ZW1wbGF0ZVxuICAgIGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLnB1dFRlbXBsYXRlKHtcbiAgICAgIG5hbWU6IFdBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRSxcbiAgICAgIGJvZHk6IG1vbml0b3JpbmdUZW1wbGF0ZVxuICAgIH0pO1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrVGVtcGxhdGUnLFxuICAgICAgJ1VwZGF0ZWQgdGhlIG1vbml0b3JpbmcgdGVtcGxhdGUnLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgY29uc3QgZXJyb3JNZXNzYWdlID0gYFNvbWV0aGluZyB3ZW50IHdyb25nIHVwZGF0aW5nIHRoZSBtb25pdG9yaW5nIHRlbXBsYXRlICR7ZXJyb3IubWVzc2FnZSB8fCBlcnJvcn1gO1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrVGVtcGxhdGUnLFxuICAgICAgZXJyb3JNZXNzYWdlXG4gICAgKTtcbiAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihtb25pdG9yaW5nRXJyb3JMb2dDb2xvcnMsIGVycm9yTWVzc2FnZSk7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbn1cblxuLyoqXG4gKiBTYXZlIGFnZW50IHN0YXR1cyBpbnRvIGVsYXN0aWNzZWFyY2gsIGNyZWF0ZSBpbmRleCBhbmQvb3IgaW5zZXJ0IGRvY3VtZW50XG4gKiBAcGFyYW0geyp9IGNvbnRleHRcbiAqIEBwYXJhbSB7Kn0gZGF0YVxuICovXG5hc3luYyBmdW5jdGlvbiBpbnNlcnRNb25pdG9yaW5nRGF0YUVsYXN0aWNzZWFyY2goY29udGV4dCwgZGF0YSkge1xuICBjb25zdCBtb25pdG9yaW5nSW5kZXhOYW1lID0gTU9OSVRPUklOR19JTkRFWF9QUkVGSVggKyBpbmRleERhdGUoTU9OSVRPUklOR19DUkVBVElPTik7XG4gICAgaWYgKCFNT05JVE9SSU5HX0VOQUJMRUQpe1xuICAgICAgcmV0dXJuO1xuICAgIH07XG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRyeUNhdGNoRm9ySW5kZXhQZXJtaXNzaW9uRXJyb3IobW9uaXRvcmluZ0luZGV4TmFtZSkgKGFzeW5jKCkgPT4ge1xuICAgICAgICBjb25zdCBleGlzdHMgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5leGlzdHMoe2luZGV4OiBtb25pdG9yaW5nSW5kZXhOYW1lfSk7XG4gICAgICAgIGlmKCFleGlzdHMuYm9keSl7XG4gICAgICAgICAgYXdhaXQgY3JlYXRlSW5kZXgoY29udGV4dCwgbW9uaXRvcmluZ0luZGV4TmFtZSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgLy8gVXBkYXRlIHRoZSBpbmRleCBjb25maWd1cmF0aW9uXG4gICAgICAgIGNvbnN0IGFwcENvbmZpZyA9IGdldENvbmZpZ3VyYXRpb24oKTtcbiAgICAgICAgY29uc3QgaW5kZXhDb25maWd1cmF0aW9uID0gYnVpbGRJbmRleFNldHRpbmdzKFxuICAgICAgICAgIGFwcENvbmZpZyxcbiAgICAgICAgICAnd2F6dWgubW9uaXRvcmluZycsXG4gICAgICAgICAgV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0lORElDRVNfU0hBUkRTXG4gICAgICAgICk7XG5cbiAgICAgICAgLy8gVG8gdXBkYXRlIHRoZSBpbmRleCBzZXR0aW5ncyB3aXRoIHRoaXMgY2xpZW50IGlzIHJlcXVpcmVkIGNsb3NlIHRoZSBpbmRleCwgdXBkYXRlIHRoZSBzZXR0aW5ncyBhbmQgb3BlbiBpdFxuICAgICAgICAvLyBOdW1iZXIgb2Ygc2hhcmRzIGlzIG5vdCBkeW5hbWljIHNvIGRlbGV0ZSB0aGF0IHNldHRpbmcgaWYgaXQncyBnaXZlblxuICAgICAgICBkZWxldGUgaW5kZXhDb25maWd1cmF0aW9uLnNldHRpbmdzLmluZGV4Lm51bWJlcl9vZl9zaGFyZHM7XG4gICAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLnB1dFNldHRpbmdzKHtcbiAgICAgICAgICBpbmRleDogbW9uaXRvcmluZ0luZGV4TmFtZSxcbiAgICAgICAgICBib2R5OiBpbmRleENvbmZpZ3VyYXRpb25cbiAgICAgICAgfSk7XG5cbiAgICAgICAgLy8gSW5zZXJ0IGRhdGEgdG8gdGhlIG1vbml0b3JpbmcgaW5kZXhcbiAgICAgICAgYXdhaXQgaW5zZXJ0RGF0YVRvSW5kZXgoY29udGV4dCwgbW9uaXRvcmluZ0luZGV4TmFtZSwgZGF0YSk7XG4gICAgICB9KSgpO1xuICAgIH1jYXRjaChlcnJvcil7XG4gICAgICBsb2coJ21vbml0b3Jpbmc6aW5zZXJ0TW9uaXRvcmluZ0RhdGFFbGFzdGljc2VhcmNoJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihlcnJvci5tZXNzYWdlKTtcbiAgICB9XG59XG5cbi8qKlxuICogSW5zZXJ0aW5nIG9uZSBkb2N1bWVudCBwZXIgYWdlbnQgaW50byBFbGFzdGljLiBCdWxrLlxuICogQHBhcmFtIHsqfSBjb250ZXh0IEVuZHBvaW50XG4gKiBAcGFyYW0ge1N0cmluZ30gaW5kZXhOYW1lIFRoZSBuYW1lIGZvciB0aGUgaW5kZXggKGUuZy4gZGFpbHk6IHdhenVoLW1vbml0b3JpbmctWVlZWS5NTS5ERClcbiAqIEBwYXJhbSB7Kn0gZGF0YVxuICovXG5hc3luYyBmdW5jdGlvbiBpbnNlcnREYXRhVG9JbmRleChjb250ZXh0LCBpbmRleE5hbWU6IHN0cmluZywgZGF0YToge2FnZW50czogYW55W10sIGFwaUhvc3R9KSB7XG4gIGNvbnN0IHsgYWdlbnRzLCBhcGlIb3N0IH0gPSBkYXRhO1xuICB0cnkge1xuICAgIGlmIChhZ2VudHMubGVuZ3RoID4gMCkge1xuICAgICAgbG9nKFxuICAgICAgICAnbW9uaXRvcmluZzppbnNlcnREYXRhVG9JbmRleCcsXG4gICAgICAgIGBCdWxrIGRhdGEgdG8gaW5kZXggJHtpbmRleE5hbWV9IGZvciAke2FnZW50cy5sZW5ndGh9IGFnZW50c2AsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG5cbiAgICAgIGNvbnN0IGJvZHlCdWxrID0gYWdlbnRzLm1hcChhZ2VudCA9PiB7XG4gICAgICAgIGNvbnN0IGFnZW50SW5mbyA9IHsuLi5hZ2VudH07XG4gICAgICAgIGFnZW50SW5mb1sndGltZXN0YW1wJ10gPSBuZXcgRGF0ZShEYXRlLm5vdygpKS50b0lTT1N0cmluZygpO1xuICAgICAgICBhZ2VudEluZm8uaG9zdCA9IGFnZW50Lm1hbmFnZXI7XG4gICAgICAgIGFnZW50SW5mby5jbHVzdGVyID0geyBuYW1lOiBhcGlIb3N0LmNsdXN0ZXJOYW1lID8gYXBpSG9zdC5jbHVzdGVyTmFtZSA6ICdkaXNhYmxlZCcgfTtcbiAgICAgICAgcmV0dXJuIGB7IFwiaW5kZXhcIjogIHsgXCJfaW5kZXhcIjogXCIke2luZGV4TmFtZX1cIiB9IH1cXG4ke0pTT04uc3RyaW5naWZ5KGFnZW50SW5mbyl9XFxuYDtcbiAgICAgIH0pLmpvaW4oJycpO1xuXG4gICAgICBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuYnVsayh7XG4gICAgICAgIGluZGV4OiBpbmRleE5hbWUsXG4gICAgICAgIGJvZHk6IGJvZHlCdWxrXG4gICAgICB9KTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ21vbml0b3Jpbmc6aW5zZXJ0RGF0YVRvSW5kZXgnLFxuICAgICAgICBgQnVsayBkYXRhIHRvIGluZGV4ICR7aW5kZXhOYW1lfSBmb3IgJHthZ2VudHMubGVuZ3RofSBhZ2VudHMgY29tcGxldGVkYCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICB9XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6aW5zZXJ0RGF0YVRvSW5kZXgnLFxuICAgICAgYEVycm9yIGluc2VydGluZyBhZ2VudCBkYXRhIGludG8gZWxhc3RpY3NlYXJjaC4gQnVsayByZXF1ZXN0IGZhaWxlZCBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8XG4gICAgICAgIGVycm9yfWBcbiAgICApO1xuICB9XG59XG5cbi8qKlxuICogQ3JlYXRlIHRoZSB3YXp1aC1tb25pdG9yaW5nIGluZGV4XG4gKiBAcGFyYW0geyp9IGNvbnRleHQgY29udGV4dFxuICogQHBhcmFtIHtTdHJpbmd9IGluZGV4TmFtZSBUaGUgbmFtZSBmb3IgdGhlIGluZGV4IChlLmcuIGRhaWx5OiB3YXp1aC1tb25pdG9yaW5nLVlZWVkuTU0uREQpXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGNyZWF0ZUluZGV4KGNvbnRleHQsIGluZGV4TmFtZTogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgaWYgKCFNT05JVE9SSU5HX0VOQUJMRUQpIHJldHVybjtcbiAgICBjb25zdCBhcHBDb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG5cbiAgICBjb25zdCBJbmRleENvbmZpZ3VyYXRpb24gPSB7XG4gICAgICBzZXR0aW5nczoge1xuICAgICAgICBpbmRleDoge1xuICAgICAgICAgIG51bWJlcl9vZl9zaGFyZHM6IGdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nKCd3YXp1aC5tb25pdG9yaW5nLnNoYXJkcycsIGFwcENvbmZpZywgV0FaVUhfSU5ERVhfU0hBUkRTKSxcbiAgICAgICAgICBudW1iZXJfb2ZfcmVwbGljYXM6IGdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nKCd3YXp1aC5tb25pdG9yaW5nLnJlcGxpY2FzJywgYXBwQ29uZmlnLCBXQVpVSF9JTkRFWF9SRVBMSUNBUylcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH07XG5cbiAgICBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5jcmVhdGUoe1xuICAgICAgaW5kZXg6IGluZGV4TmFtZSxcbiAgICAgIGJvZHk6IEluZGV4Q29uZmlndXJhdGlvblxuICAgIH0pO1xuXG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y3JlYXRlSW5kZXgnLFxuICAgICAgYFN1Y2Nlc3NmdWxseSBjcmVhdGVkIG5ldyBpbmRleDogJHtpbmRleE5hbWV9YCxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9IGBDb3VsZCBub3QgY3JlYXRlICR7aW5kZXhOYW1lfSBpbmRleCBvbiBlbGFzdGljc2VhcmNoIGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YDtcbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzpjcmVhdGVJbmRleCcsXG4gICAgICBlcnJvck1lc3NhZ2VcbiAgICApO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKGVycm9yTWVzc2FnZSk7XG4gIH1cbn1cblxuLyoqXG4qIFdhaXQgdW50aWwgS2liYW5hIHNlcnZlciBpcyByZWFkeVxuKi9cbmFzeW5jIGZ1bmN0aW9uIGNoZWNrS2liYW5hU3RhdHVzKGNvbnRleHQpIHtcbiB0cnkge1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrS2liYW5hU3RhdHVzJyxcbiAgICAgICdXYWl0aW5nIGZvciBLaWJhbmEgYW5kIEVsYXN0aWNzZWFyY2ggc2VydmVycyB0byBiZSByZWFkeS4uLicsXG4gICAgICAnZGVidWcnXG4gICAgKTtcblxuICAgYXdhaXQgY2hlY2tFbGFzdGljc2VhcmNoU2VydmVyKGNvbnRleHQpO1xuICAgYXdhaXQgaW5pdChjb250ZXh0KTtcbiAgIHJldHVybjtcbiB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrS2liYW5hU3RhdHVzJyxcbiAgICAgIGVycm9yLm1lc2FnZSB8fGVycm9yXG4gICAgKTtcbiAgICB0cnl7XG4gICAgICBhd2FpdCBkZWxheSgzMDAwKTtcbiAgICAgIGF3YWl0IGNoZWNrS2liYW5hU3RhdHVzKGNvbnRleHQpO1xuICAgIH1jYXRjaChlcnJvcil7fTtcbiB9XG59XG5cblxuLyoqXG4gKiBDaGVjayBFbGFzdGljc2VhcmNoIFNlcnZlciBzdGF0dXMgYW5kIEtpYmFuYSBpbmRleCBwcmVzZW5jZVxuICovXG5hc3luYyBmdW5jdGlvbiBjaGVja0VsYXN0aWNzZWFyY2hTZXJ2ZXIoY29udGV4dCkge1xuICB0cnkge1xuICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgaW5kZXg6IGNvbnRleHQuc2VydmVyLmNvbmZpZy5raWJhbmEuaW5kZXhcbiAgICB9KTtcblxuICAgIHJldHVybiBkYXRhLmJvZHk7XG4gICAgLy8gVE9ETzogY2hlY2sgaWYgRWxhc3RpY3NlYXJjaCBjYW4gcmVjZWl2ZSByZXF1ZXN0c1xuICAgIC8vIGlmIChkYXRhKSB7XG4gICAgLy8gICBjb25zdCBwbHVnaW5zRGF0YSA9IGF3YWl0IHRoaXMuc2VydmVyLnBsdWdpbnMuZWxhc3RpY3NlYXJjaC53YWl0VW50aWxSZWFkeSgpO1xuICAgIC8vICAgcmV0dXJuIHBsdWdpbnNEYXRhO1xuICAgIC8vIH1cbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZGF0YSk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKCdtb25pdG9yaW5nOmNoZWNrRWxhc3RpY3NlYXJjaFNlcnZlcicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gIH1cbn1cblxuY29uc3QgZmFrZVJlc3BvbnNlRW5kcG9pbnQgPSB7XG4gIG9rOiAoYm9keTogYW55KSA9PiBib2R5LFxuICBjdXN0b206IChib2R5OiBhbnkpID0+IGJvZHksXG59XG4vKipcbiAqIEdldCBBUEkgY29uZmlndXJhdGlvbiBmcm9tIGVsYXN0aWMgYW5kIGNhbGxiYWNrIHRvIGxvYWRDcmVkZW50aWFsc1xuICovXG5hc3luYyBmdW5jdGlvbiBnZXRIb3N0c0NvbmZpZ3VyYXRpb24oKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgaG9zdHMgPSBhd2FpdCB3YXp1aEhvc3RDb250cm9sbGVyLmdldEhvc3RzRW50cmllcyhmYWxzZSwgZmFsc2UsIGZha2VSZXNwb25zZUVuZHBvaW50KTtcbiAgICBpZiAoaG9zdHMuYm9keS5sZW5ndGgpIHtcbiAgICAgIHJldHVybiBob3N0cy5ib2R5O1xuICAgIH07XG5cbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzpnZXRDb25maWcnLFxuICAgICAgJ1RoZXJlIGFyZSBubyBXYXp1aCBBUEkgZW50cmllcyB5ZXQnLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHtcbiAgICAgIGVycm9yOiAnbm8gY3JlZGVudGlhbHMnLFxuICAgICAgZXJyb3JfY29kZTogMVxuICAgIH0pO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZygnbW9uaXRvcmluZzpnZXRIb3N0c0NvbmZpZ3VyYXRpb24nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Qoe1xuICAgICAgZXJyb3I6ICdubyB3YXp1aCBob3N0cycsXG4gICAgICBlcnJvcl9jb2RlOiAyXG4gICAgfSk7XG4gIH1cbn1cblxuLyoqXG4gICAqIFRhc2sgdXNlZCBieSB0aGUgY3JvbiBqb2IuXG4gICAqL1xuYXN5bmMgZnVuY3Rpb24gY3JvblRhc2soY29udGV4dCkge1xuICB0cnkge1xuICAgIGNvbnN0IHRlbXBsYXRlTW9uaXRvcmluZyA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLmdldFRlbXBsYXRlKHtuYW1lOiBXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUV9KTtcblxuICAgIGNvbnN0IGFwaUhvc3RzID0gYXdhaXQgZ2V0SG9zdHNDb25maWd1cmF0aW9uKCk7XG4gICAgY29uc3QgYXBpSG9zdHNVbmlxdWUgPSAoYXBpSG9zdHMgfHwgW10pLmZpbHRlcihcbiAgICAgIChhcGlIb3N0LCBpbmRleCwgc2VsZikgPT5cbiAgICAgICAgaW5kZXggPT09XG4gICAgICAgIHNlbGYuZmluZEluZGV4KFxuICAgICAgICAgIHQgPT5cbiAgICAgICAgICAgIHQudXNlciA9PT0gYXBpSG9zdC51c2VyICYmXG4gICAgICAgICAgICB0LnBhc3N3b3JkID09PSBhcGlIb3N0LnBhc3N3b3JkICYmXG4gICAgICAgICAgICB0LnVybCA9PT0gYXBpSG9zdC51cmwgJiZcbiAgICAgICAgICAgIHQucG9ydCA9PT0gYXBpSG9zdC5wb3J0XG4gICAgICAgIClcbiAgICApO1xuICAgIGZvcihsZXQgYXBpSG9zdCBvZiBhcGlIb3N0c1VuaXF1ZSl7XG4gICAgICB0cnl7XG4gICAgICAgIGNvbnN0IHsgYWdlbnRzLCBhcGlIb3N0OiBob3N0fSA9IGF3YWl0IGdldEFwaUluZm8oY29udGV4dCwgYXBpSG9zdCk7XG4gICAgICAgIGF3YWl0IGluc2VydE1vbml0b3JpbmdEYXRhRWxhc3RpY3NlYXJjaChjb250ZXh0LCB7YWdlbnRzLCBhcGlIb3N0OiBob3N0fSk7XG4gICAgICB9Y2F0Y2goZXJyb3Ipe1xuXG4gICAgICB9O1xuICAgIH1cbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAvLyBSZXRyeSB0byBjYWxsIGl0c2VsZiBhZ2FpbiBpZiBLaWJhbmEgaW5kZXggaXMgbm90IHJlYWR5IHlldFxuICAgIC8vIHRyeSB7XG4gICAgLy8gICBpZiAoXG4gICAgLy8gICAgIHRoaXMud3pXcmFwcGVyLmJ1aWxkaW5nS2liYW5hSW5kZXggfHxcbiAgICAvLyAgICAgKChlcnJvciB8fCB7fSkuc3RhdHVzID09PSA0MDQgJiZcbiAgICAvLyAgICAgICAoZXJyb3IgfHwge30pLmRpc3BsYXlOYW1lID09PSAnTm90Rm91bmQnKVxuICAgIC8vICAgKSB7XG4gICAgLy8gICAgIGF3YWl0IGRlbGF5KDEwMDApO1xuICAgIC8vICAgICByZXR1cm4gY3JvblRhc2soY29udGV4dCk7XG4gICAgLy8gICB9XG4gICAgLy8gfSBjYXRjaCAoZXJyb3IpIHt9IC8vZXNsaW50LWRpc2FibGUtbGluZVxuXG4gICAgbG9nKCdtb25pdG9yaW5nOmNyb25UYXNrJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gIH1cbn1cblxuLyoqXG4gKiBHZXQgQVBJIGFuZCBhZ2VudHMgaW5mb1xuICogQHBhcmFtIGNvbnRleHRcbiAqIEBwYXJhbSBhcGlIb3N0XG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGdldEFwaUluZm8oY29udGV4dCwgYXBpSG9zdCl7XG4gIHRyeXtcbiAgICBsb2coJ21vbml0b3Jpbmc6Z2V0QXBpSW5mbycsIGBHZXR0aW5nIEFQSSBpbmZvIGZvciAke2FwaUhvc3QuaWR9YCwgJ2RlYnVnJyk7XG4gICAgY29uc3QgcmVzcG9uc2VJc0NsdXN0ZXIgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdCgnR0VUJywgJy9jbHVzdGVyL3N0YXR1cycsIHt9LCB7IGFwaUhvc3RJRDogYXBpSG9zdC5pZCB9KTtcbiAgICBjb25zdCBpc0NsdXN0ZXIgPSAoKChyZXNwb25zZUlzQ2x1c3RlciB8fCB7fSkuZGF0YSB8fCB7fSkuZGF0YSB8fCB7fSkuZW5hYmxlZCA9PT0gJ3llcyc7XG4gICAgaWYoaXNDbHVzdGVyKXtcbiAgICAgIGNvbnN0IHJlc3BvbnNlQ2x1c3RlckluZm8gPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdCgnR0VUJywgYC9jbHVzdGVyL2xvY2FsL2luZm9gLCB7fSwgIHsgYXBpSG9zdElEOiBhcGlIb3N0LmlkIH0pO1xuICAgICAgYXBpSG9zdC5jbHVzdGVyTmFtZSA9IHJlc3BvbnNlQ2x1c3RlckluZm8uZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLmNsdXN0ZXI7XG4gICAgfTtcbiAgICBjb25zdCBhZ2VudHMgPSBhd2FpdCBmZXRjaEFsbEFnZW50c0Zyb21BcGlIb3N0KGNvbnRleHQsIGFwaUhvc3QpO1xuICAgIHJldHVybiB7IGFnZW50cywgYXBpSG9zdCB9O1xuICB9Y2F0Y2goZXJyb3Ipe1xuICAgIGxvZygnbW9uaXRvcmluZzpnZXRBcGlJbmZvJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbn07XG5cbi8qKlxuICogRmV0Y2ggYWxsIGFnZW50cyBmb3IgdGhlIEFQSSBwcm92aWRlZFxuICogQHBhcmFtIGNvbnRleHRcbiAqIEBwYXJhbSBhcGlIb3N0XG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QoY29udGV4dCwgYXBpSG9zdCl7XG4gIGxldCBhZ2VudHMgPSBbXTtcbiAgdHJ5e1xuICAgIGxvZygnbW9uaXRvcmluZzpmZXRjaEFsbEFnZW50c0Zyb21BcGlIb3N0JywgYEdldHRpbmcgYWxsIGFnZW50cyBmcm9tIEFwaUlEOiAke2FwaUhvc3QuaWR9YCwgJ2RlYnVnJyk7XG4gICAgY29uc3QgcmVzcG9uc2VBZ2VudHNDb3VudCA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgJ0dFVCcsXG4gICAgICAnL2FnZW50cycsXG4gICAgICB7XG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIG9mZnNldDogMCxcbiAgICAgICAgICBsaW1pdDogMSxcbiAgICAgICAgICBxOiAnaWQhPTAwMCdcbiAgICAgICAgfVxuICAgICAgfSwge2FwaUhvc3RJRDogYXBpSG9zdC5pZH0pO1xuXG4gICAgY29uc3QgYWdlbnRzQ291bnQgPSByZXNwb25zZUFnZW50c0NvdW50LmRhdGEuZGF0YS50b3RhbF9hZmZlY3RlZF9pdGVtcztcbiAgICBsb2coJ21vbml0b3Jpbmc6ZmV0Y2hBbGxBZ2VudHNGcm9tQXBpSG9zdCcsIGBBcGlJRDogJHthcGlIb3N0LmlkfSwgQWdlbnQgY291bnQ6ICR7YWdlbnRzQ291bnR9YCwgJ2RlYnVnJyk7XG5cbiAgICBsZXQgcGF5bG9hZCA9IHtcbiAgICAgIG9mZnNldDogMCxcbiAgICAgIGxpbWl0OiA1MDAsXG4gICAgICBxOiAnaWQhPTAwMCdcbiAgICB9O1xuXG4gICAgd2hpbGUgKGFnZW50cy5sZW5ndGggPCBhZ2VudHNDb3VudCAmJiBwYXlsb2FkLm9mZnNldCA8IGFnZW50c0NvdW50KSB7XG4gICAgICB0cnl7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlQWdlbnRzID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9hZ2VudHNgLFxuICAgICAgICAgIHtwYXJhbXM6IHBheWxvYWR9LFxuICAgICAgICAgIHthcGlIb3N0SUQ6IGFwaUhvc3QuaWR9XG4gICAgICAgICk7XG4gICAgICAgIGFnZW50cyA9IFsuLi5hZ2VudHMsIC4uLnJlc3BvbnNlQWdlbnRzLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc107XG4gICAgICAgIHBheWxvYWQub2Zmc2V0ICs9IHBheWxvYWQubGltaXQ7XG4gICAgICB9Y2F0Y2goZXJyb3Ipe1xuICAgICAgICBsb2coJ21vbml0b3Jpbmc6ZmV0Y2hBbGxBZ2VudHNGcm9tQXBpSG9zdCcsIGBBcGlJRDogJHthcGlIb3N0LmlkfSwgRXJyb3IgcmVxdWVzdCB3aXRoIG9mZnNldC9saW1pdCAke3BheWxvYWQub2Zmc2V0fS8ke3BheWxvYWQubGltaXR9OiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YCk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBhZ2VudHM7XG4gIH1jYXRjaChlcnJvcil7XG4gICAgbG9nKCdtb25pdG9yaW5nOmZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QnLCBgQXBpSUQ6ICR7YXBpSG9zdC5pZH0uIEVycm9yOiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YCk7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbn07XG5cbi8qKlxuICogU3RhcnQgdGhlIGNyb24gam9iXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBqb2JNb25pdG9yaW5nUnVuKGNvbnRleHQpIHtcbiAgLy8gSW5pdCB0aGUgbW9uaXRvcmluZyB2YXJpYWJsZXNcbiAgaW5pdE1vbml0b3JpbmdDb25maWd1cmF0aW9uKGNvbnRleHQpO1xuICAvLyBDaGVjayBLaWJhbmEgaW5kZXggYW5kIGlmIGl0IGlzIHByZXBhcmVkLCBzdGFydCB0aGUgaW5pdGlhbGl6YXRpb24gb2YgV2F6dWggQXBwLlxuICBhd2FpdCBjaGVja0tpYmFuYVN0YXR1cyhjb250ZXh0KTtcbiAgLy8gLy8gUnVuIHRoZSBjcm9uIGpvYiBvbmx5IGl0IGl0J3MgZW5hYmxlZFxuICBpZiAoTU9OSVRPUklOR19FTkFCTEVEKSB7XG4gICAgY3JvblRhc2soY29udGV4dCk7XG4gICAgY3Jvbi5zY2hlZHVsZShNT05JVE9SSU5HX0NST05fRlJFUSwgKCkgPT4gY3JvblRhc2soY29udGV4dCkpO1xuICB9XG59XG5cbiJdfQ==