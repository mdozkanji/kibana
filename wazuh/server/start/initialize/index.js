"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jobInitializeRun = jobInitializeRun;

var _logger = require("../../lib/logger");

var _package = _interopRequireDefault(require("../../../package.json"));

var _kibanaTemplate = require("../../integration-files/kibana-template");

var _getConfiguration = require("../../lib/get-configuration");

var _os = require("os");

var _fs = _interopRequireDefault(require("fs"));

var _manageHosts = require("../../lib/manage-hosts");

var _constants = require("../../../common/constants");

var _filesystem = require("../../lib/filesystem");

var _tryCatchForIndexPermissionError = require("../tryCatchForIndexPermissionError");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/*
 * Wazuh app - Module for app initialization
 * Copyright (C) 2015-2021 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const manageHosts = new _manageHosts.ManageHosts();

function jobInitializeRun(context) {
  const KIBANA_INDEX = context.server.config.kibana.index;
  (0, _logger.log)('initialize', `Kibana index: ${KIBANA_INDEX}`, 'info');
  (0, _logger.log)('initialize', `App revision: ${_package.default.revision}`, 'info');
  let configurationFile = {};
  let pattern = null; // Read config from package.json and wazuh.yml

  try {
    configurationFile = (0, _getConfiguration.getConfiguration)();
    pattern = configurationFile && typeof configurationFile.pattern !== 'undefined' ? configurationFile.pattern : _constants.WAZUH_ALERTS_PATTERN; // global.XPACK_RBAC_ENABLED =
    //   configurationFile &&
    //     typeof configurationFile['xpack.rbac.enabled'] !== 'undefined'
    //     ? configurationFile['xpack.rbac.enabled']
    //     : true;
  } catch (error) {
    (0, _logger.log)('initialize', error.message || error);
    context.wazuh.logger.error('Something went wrong while reading the configuration.' + (error.message || error));
  }

  try {
    // RAM in MB
    const ram = Math.ceil((0, _os.totalmem)() / 1024 / 1024);
    (0, _logger.log)('initialize', `Total RAM: ${ram}MB`, 'info');
  } catch (error) {
    (0, _logger.log)('initialize', `Could not check total RAM due to: ${error.message || error}`);
  } // Save Wazuh App setup


  const saveConfiguration = async () => {
    try {
      const commonDate = new Date().toISOString();
      const configuration = {
        name: 'Wazuh App',
        'app-version': _package.default.version,
        revision: _package.default.revision,
        installationDate: commonDate,
        lastRestart: commonDate,
        hosts: {}
      };

      try {
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDataDirectoryIfNotExists)('config');
        await _fs.default.writeFileSync(_constants.WAZUH_DATA_CONFIG_REGISTRY_PATH, JSON.stringify(configuration), 'utf8');
        (0, _logger.log)('initialize:saveConfiguration', 'Wazuh configuration registry inserted', 'debug');
      } catch (error) {
        (0, _logger.log)('initialize:saveConfiguration', error.message || error);
        context.wazuh.logger.error('Could not create Wazuh configuration registry');
      }
    } catch (error) {
      (0, _logger.log)('initialize:saveConfiguration', error.message || error);
      context.wazuh.logger.error('Error creating wazuh-version registry');
    }
  };
  /**
   * Checks if the .wazuh index exist in order to migrate to wazuh.yml
   */


  const checkWazuhIndex = (0, _tryCatchForIndexPermissionError.tryCatchForIndexPermissionError)(_constants.WAZUH_INDEX)(async () => {
    (0, _logger.log)('initialize:checkWazuhIndex', `Checking ${_constants.WAZUH_INDEX} index.`, 'debug');
    const result = await context.core.elasticsearch.client.asInternalUser.indices.exists({
      index: _constants.WAZUH_INDEX
    });

    if (result.body) {
      const data = await context.core.elasticsearch.client.asInternalUser.search({
        index: _constants.WAZUH_INDEX,
        size: 100
      });
      const apiEntries = (((data || {}).body || {}).hits || {}).hits || [];
      await manageHosts.migrateFromIndex(apiEntries);
      (0, _logger.log)('initialize:checkWazuhIndex', `Index ${_constants.WAZUH_INDEX} will be removed and its content will be migrated to wazuh.yml`, 'debug'); // Check if all APIs entries were migrated properly and delete it from the .wazuh index

      await checkProperlyMigrate();
      await context.core.elasticsearch.client.asInternalUser.indices.delete({
        index: _constants.WAZUH_INDEX
      });
    }
  });
  /**
   * Checks if the API entries were properly migrated
   * @param {Array} migratedApis
   */

  const checkProperlyMigrate = async () => {
    try {
      let apisIndex = await await context.core.elasticsearch.client.asInternalUser.search({
        index: _constants.WAZUH_INDEX,
        size: 100
      });
      const hosts = await manageHosts.getHosts();
      apisIndex = ((apisIndex.body || {}).hits || {}).hits || [];
      const apisIndexKeys = apisIndex.map(api => {
        return api._id;
      });
      const hostsKeys = hosts.map(api => {
        return Object.keys(api)[0];
      }); // Get into an array the API entries that were not migrated, if the length is 0 then all the API entries were properly migrated.

      const rest = apisIndexKeys.filter(k => {
        return !hostsKeys.includes(k);
      });

      if (rest.length) {
        throw new Error(`Cannot migrate all API entries, missed entries: (${rest.toString()})`);
      }

      (0, _logger.log)('initialize:checkProperlyMigrate', 'The API entries migration was successful', 'debug');
    } catch (error) {
      (0, _logger.log)('initialize:checkProperlyMigrate', `${error}`, 'error');
      return Promise.reject(error);
    }
  };
  /**
   * Checks if the .wazuh-version exists, in this case it will be deleted and the wazuh-registry.json will be created
   */


  const checkWazuhRegistry = async () => {
    try {
      (0, _logger.log)('initialize:checkwazuhRegistry', 'Checking wazuh-version registry.', 'debug');

      try {
        const exists = await context.core.elasticsearch.client.asInternalUser.indices.exists({
          index: _constants.WAZUH_VERSION_INDEX
        });

        if (exists.body) {
          await context.core.elasticsearch.client.asInternalUser.indices.delete({
            index: _constants.WAZUH_VERSION_INDEX
          });
          (0, _logger.log)('initialize[checkwazuhRegistry]', `Successfully deleted old ${_constants.WAZUH_VERSION_INDEX} index.`, 'debug');
        }

        ;
      } catch (error) {
        (0, _logger.log)('initialize[checkwazuhRegistry]', `No need to delete old ${_constants.WAZUH_VERSION_INDEX} index`, 'debug');
      }

      if (!_fs.default.existsSync(_constants.WAZUH_DATA_KIBANA_BASE_ABSOLUTE_PATH)) {
        throw new Error(`The data directory is missing in the Kibana root instalation. Create the directory in ${_constants.WAZUH_DATA_KIBANA_BASE_ABSOLUTE_PATH} and give it the required permissions (sudo mkdir ${_constants.WAZUH_DATA_KIBANA_BASE_ABSOLUTE_PATH};sudo chown -R kibana:kibana ${_constants.WAZUH_DATA_KIBANA_BASE_ABSOLUTE_PATH}). After restart the Kibana service.`);
      }

      ;

      if (!_fs.default.existsSync(_constants.WAZUH_DATA_CONFIG_REGISTRY_PATH)) {
        (0, _logger.log)('initialize:checkwazuhRegistry', 'wazuh-version registry does not exist. Initializing configuration.', 'debug'); // Create the app registry file for the very first time

        await saveConfiguration();
      } else {
        // If this function fails, it throws an exception
        const source = JSON.parse(_fs.default.readFileSync(_constants.WAZUH_DATA_CONFIG_REGISTRY_PATH, 'utf8')); // Check if the stored revision differs from the package.json revision

        const isUpgradedApp = _package.default.revision !== source.revision || _package.default.version !== source['app-version']; // Rebuild the registry file if revision or version fields are differents

        if (isUpgradedApp) {
          (0, _logger.log)('initialize:checkwazuhRegistry', 'Wazuh app revision or version changed, regenerating wazuh-version registry', 'info'); // Rebuild registry file in blank

          await saveConfiguration();
        }
      }
    } catch (error) {
      return Promise.reject(error);
    }
  }; // Init function. Check for "wazuh-version" document existance.


  const init = async () => {
    await Promise.all([checkWazuhIndex(), checkWazuhRegistry()]);
  };

  const createKibanaTemplate = () => {
    (0, _logger.log)('initialize:createKibanaTemplate', `Creating template for ${KIBANA_INDEX}`, 'debug');

    try {
      _kibanaTemplate.kibanaTemplate.template = KIBANA_INDEX + '*';
    } catch (error) {
      (0, _logger.log)('initialize:createKibanaTemplate', error.message || error);
      context.wazuh.logger.error('Exception: ' + error.message || error);
    }

    return context.core.elasticsearch.client.asInternalUser.indices.putTemplate({
      name: _constants.WAZUH_KIBANA_TEMPLATE_NAME,
      order: 0,
      create: true,
      body: _kibanaTemplate.kibanaTemplate
    });
  };

  const createEmptyKibanaIndex = async () => {
    try {
      (0, _logger.log)('initialize:createEmptyKibanaIndex', `Creating ${KIBANA_INDEX} index.`, 'info');
      await context.core.elasticsearch.client.asInternalUser.indices.create({
        index: KIBANA_INDEX
      });
      (0, _logger.log)('initialize:createEmptyKibanaIndex', `Successfully created ${KIBANA_INDEX} index.`, 'debug');
      await init();
      return;
    } catch (error) {
      return Promise.reject(new Error(`Error creating ${KIBANA_INDEX} index due to ${error.message || error}`));
    }
  };

  const fixKibanaTemplate = async () => {
    try {
      await createKibanaTemplate();
      (0, _logger.log)('initialize:checkKibanaStatus', `Successfully created ${KIBANA_INDEX} template.`, 'debug');
      await createEmptyKibanaIndex();
      return;
    } catch (error) {
      return Promise.reject(new Error(`Error creating template for ${KIBANA_INDEX} due to ${error.message || error}`));
    }
  };

  const getTemplateByName = async () => {
    try {
      await context.core.elasticsearch.client.asInternalUser.indices.getTemplate({
        name: _constants.WAZUH_KIBANA_TEMPLATE_NAME
      });
      (0, _logger.log)('initialize:checkKibanaStatus', `No need to create the ${KIBANA_INDEX} template, already exists.`, 'debug');
      await createEmptyKibanaIndex();
      return;
    } catch (error) {
      (0, _logger.log)('initialize:checkKibanaStatus', error.message || error);
      return fixKibanaTemplate();
    }
  }; // Does Kibana index exist?


  const checkKibanaStatus = async () => {
    try {
      const response = await context.core.elasticsearch.client.asInternalUser.indices.exists({
        index: KIBANA_INDEX
      });

      if (response.body) {
        // It exists, initialize!
        await init();
      } else {
        // No Kibana index created...
        (0, _logger.log)('initialize:checkKibanaStatus', `Not found ${KIBANA_INDEX} index`, 'info');
        await getTemplateByName();
      }
    } catch (error) {
      (0, _logger.log)('initialize:checkKibanaStatus', error.message || error);
      context.wazuh.logger.error(error.message || error);
    }
  }; // Wait until Elasticsearch js is ready


  const checkStatus = async () => {
    try {
      // TODO: wait until elasticsearch is ready?
      // await server.plugins.elasticsearch.waitUntilReady();
      return await checkKibanaStatus();
    } catch (error) {
      (0, _logger.log)('initialize:checkStatus', 'Waiting for elasticsearch plugin to be ready...', 'debug');
      setTimeout(() => checkStatus(), 3000);
    }
  }; // Check Kibana index and if it is prepared, start the initialization of Wazuh App.


  return checkStatus();
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbIm1hbmFnZUhvc3RzIiwiTWFuYWdlSG9zdHMiLCJqb2JJbml0aWFsaXplUnVuIiwiY29udGV4dCIsIktJQkFOQV9JTkRFWCIsInNlcnZlciIsImNvbmZpZyIsImtpYmFuYSIsImluZGV4IiwicGFja2FnZUpTT04iLCJyZXZpc2lvbiIsImNvbmZpZ3VyYXRpb25GaWxlIiwicGF0dGVybiIsIldBWlVIX0FMRVJUU19QQVRURVJOIiwiZXJyb3IiLCJtZXNzYWdlIiwid2F6dWgiLCJsb2dnZXIiLCJyYW0iLCJNYXRoIiwiY2VpbCIsInNhdmVDb25maWd1cmF0aW9uIiwiY29tbW9uRGF0ZSIsIkRhdGUiLCJ0b0lTT1N0cmluZyIsImNvbmZpZ3VyYXRpb24iLCJuYW1lIiwidmVyc2lvbiIsImluc3RhbGxhdGlvbkRhdGUiLCJsYXN0UmVzdGFydCIsImhvc3RzIiwiZnMiLCJ3cml0ZUZpbGVTeW5jIiwiV0FaVUhfREFUQV9DT05GSUdfUkVHSVNUUllfUEFUSCIsIkpTT04iLCJzdHJpbmdpZnkiLCJjaGVja1dhenVoSW5kZXgiLCJXQVpVSF9JTkRFWCIsInJlc3VsdCIsImNvcmUiLCJlbGFzdGljc2VhcmNoIiwiY2xpZW50IiwiYXNJbnRlcm5hbFVzZXIiLCJpbmRpY2VzIiwiZXhpc3RzIiwiYm9keSIsImRhdGEiLCJzZWFyY2giLCJzaXplIiwiYXBpRW50cmllcyIsImhpdHMiLCJtaWdyYXRlRnJvbUluZGV4IiwiY2hlY2tQcm9wZXJseU1pZ3JhdGUiLCJkZWxldGUiLCJhcGlzSW5kZXgiLCJnZXRIb3N0cyIsImFwaXNJbmRleEtleXMiLCJtYXAiLCJhcGkiLCJfaWQiLCJob3N0c0tleXMiLCJPYmplY3QiLCJrZXlzIiwicmVzdCIsImZpbHRlciIsImsiLCJpbmNsdWRlcyIsImxlbmd0aCIsIkVycm9yIiwidG9TdHJpbmciLCJQcm9taXNlIiwicmVqZWN0IiwiY2hlY2tXYXp1aFJlZ2lzdHJ5IiwiV0FaVUhfVkVSU0lPTl9JTkRFWCIsImV4aXN0c1N5bmMiLCJXQVpVSF9EQVRBX0tJQkFOQV9CQVNFX0FCU09MVVRFX1BBVEgiLCJzb3VyY2UiLCJwYXJzZSIsInJlYWRGaWxlU3luYyIsImlzVXBncmFkZWRBcHAiLCJpbml0IiwiYWxsIiwiY3JlYXRlS2liYW5hVGVtcGxhdGUiLCJraWJhbmFUZW1wbGF0ZSIsInRlbXBsYXRlIiwicHV0VGVtcGxhdGUiLCJXQVpVSF9LSUJBTkFfVEVNUExBVEVfTkFNRSIsIm9yZGVyIiwiY3JlYXRlIiwiY3JlYXRlRW1wdHlLaWJhbmFJbmRleCIsImZpeEtpYmFuYVRlbXBsYXRlIiwiZ2V0VGVtcGxhdGVCeU5hbWUiLCJnZXRUZW1wbGF0ZSIsImNoZWNrS2liYW5hU3RhdHVzIiwicmVzcG9uc2UiLCJjaGVja1N0YXR1cyIsInNldFRpbWVvdXQiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7OztBQXBCQTs7Ozs7Ozs7Ozs7QUFzQkEsTUFBTUEsV0FBVyxHQUFHLElBQUlDLHdCQUFKLEVBQXBCOztBQUVPLFNBQVNDLGdCQUFULENBQTBCQyxPQUExQixFQUFtQztBQUN4QyxRQUFNQyxZQUFZLEdBQUdELE9BQU8sQ0FBQ0UsTUFBUixDQUFlQyxNQUFmLENBQXNCQyxNQUF0QixDQUE2QkMsS0FBbEQ7QUFDQSxtQkFBSSxZQUFKLEVBQW1CLGlCQUFnQkosWUFBYSxFQUFoRCxFQUFtRCxNQUFuRDtBQUNBLG1CQUFJLFlBQUosRUFBbUIsaUJBQWdCSyxpQkFBWUMsUUFBUyxFQUF4RCxFQUEyRCxNQUEzRDtBQUVBLE1BQUlDLGlCQUFpQixHQUFHLEVBQXhCO0FBQ0EsTUFBSUMsT0FBTyxHQUFHLElBQWQsQ0FOd0MsQ0FPeEM7O0FBQ0EsTUFBSTtBQUNGRCxJQUFBQSxpQkFBaUIsR0FBRyx5Q0FBcEI7QUFFQUMsSUFBQUEsT0FBTyxHQUNMRCxpQkFBaUIsSUFBSSxPQUFPQSxpQkFBaUIsQ0FBQ0MsT0FBekIsS0FB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QWxCLEVBQXNCLElBQXRCLENBQVY7QUFDRDtBQUNGLEdBYkQsQ0EvVXdDLENBOFZ4Qzs7O0FBQ0EsU0FBT0EsV0FBVyxFQUFsQjtBQUNEIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgYXBwIGluaXRpYWxpemF0aW9uXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMSBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vLi4vbGliL2xvZ2dlcic7XG5pbXBvcnQgcGFja2FnZUpTT04gZnJvbSAnLi4vLi4vLi4vcGFja2FnZS5qc29uJztcbmltcG9ydCB7IGtpYmFuYVRlbXBsYXRlIH0gZnJvbSAnLi4vLi4vaW50ZWdyYXRpb24tZmlsZXMva2liYW5hLXRlbXBsYXRlJztcbmltcG9ydCB7IGdldENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi8uLi9saWIvZ2V0LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgdG90YWxtZW0gfSBmcm9tICdvcyc7XG5pbXBvcnQgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHsgTWFuYWdlSG9zdHMgfSBmcm9tICcuLi8uLi9saWIvbWFuYWdlLWhvc3RzJztcbmltcG9ydCB7IFdBWlVIX0FMRVJUU19QQVRURVJOLCBXQVpVSF9EQVRBX0NPTkZJR19SRUdJU1RSWV9QQVRILCBXQVpVSF9JTkRFWCwgV0FaVUhfVkVSU0lPTl9JTkRFWCwgV0FaVUhfS0lCQU5BX1RFTVBMQVRFX05BTUUsIFdBWlVIX0RBVEFfS0lCQU5BX0JBU0VfQUJTT0xVVEVfUEFUSCB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzIH0gZnJvbSAnLi4vLi4vbGliL2ZpbGVzeXN0ZW0nO1xuaW1wb3J0IHsgdHJ5Q2F0Y2hGb3JJbmRleFBlcm1pc3Npb25FcnJvciB9IGZyb20gJy4uL3RyeUNhdGNoRm9ySW5kZXhQZXJtaXNzaW9uRXJyb3InO1xuXG5jb25zdCBtYW5hZ2VIb3N0cyA9IG5ldyBNYW5hZ2VIb3N0cygpO1xuXG5leHBvcnQgZnVuY3Rpb24gam9iSW5pdGlhbGl6ZVJ1bihjb250ZXh0KSB7XG4gIGNvbnN0IEtJQkFOQV9JTkRFWCA9IGNvbnRleHQuc2VydmVyLmNvbmZpZy5raWJhbmEuaW5kZXg7XG4gIGxvZygnaW5pdGlhbGl6ZScsIGBLaWJhbmEgaW5kZXg6ICR7S0lCQU5BX0lOREVYfWAsICdpbmZvJyk7XG4gIGxvZygnaW5pdGlhbGl6ZScsIGBBcHAgcmV2aXNpb246ICR7cGFja2FnZUpTT04ucmV2aXNpb259YCwgJ2luZm8nKTtcblxuICBsZXQgY29uZmlndXJhdGlvbkZpbGUgPSB7fTtcbiAgbGV0IHBhdHRlcm4gPSBudWxsO1xuICAvLyBSZWFkIGNvbmZpZyBmcm9tIHBhY2thZ2UuanNvbiBhbmQgd2F6dWgueW1sXG4gIHRyeSB7XG4gICAgY29uZmlndXJhdGlvbkZpbGUgPSBnZXRDb25maWd1cmF0aW9uKCk7XG5cbiAgICBwYXR0ZXJuID1cbiAgICAgIGNvbmZpZ3VyYXRpb25GaWxlICYmIHR5cGVvZiBjb25maWd1cmF0aW9uRmlsZS5wYXR0ZXJuICE9PSAndW5kZWZpbmVkJ1xuICAgICAgICA/IGNvbmZpZ3VyYXRpb25GaWxlLnBhdHRlcm5cbiAgICAgICAgOiBXQVpVSF9BTEVSVFNfUEFUVEVSTjtcbiAgICAvLyBnbG9iYWwuWFBBQ0tfUkJBQ19FTkFCTEVEID1cbiAgICAvLyAgIGNvbmZpZ3VyYXRpb25GaWxlICYmXG4gICAgLy8gICAgIHR5cGVvZiBjb25maWd1cmF0aW9uRmlsZVsneHBhY2sucmJhYy5lbmFibGVkJ10gIT09ICd1bmRlZmluZWQnXG4gICAgLy8gICAgID8gY29uZmlndXJhdGlvbkZpbGVbJ3hwYWNrLnJiYWMuZW5hYmxlZCddXG4gICAgLy8gICAgIDogdHJ1ZTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBsb2coJ2luaXRpYWxpemUnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihcbiAgICAgICdTb21ldGhpbmcgd2VudCB3cm9uZyB3aGlsZSByZWFkaW5nIHRoZSBjb25maWd1cmF0aW9uLicgKyAoZXJyb3IubWVzc2FnZSB8fCBlcnJvcilcbiAgICApO1xuICB9XG5cbiAgdHJ5IHtcbiAgICAvLyBSQU0gaW4gTUJcbiAgICBjb25zdCByYW0gPSBNYXRoLmNlaWwodG90YWxtZW0oKSAvIDEwMjQgLyAxMDI0KTtcbiAgICBsb2coJ2luaXRpYWxpemUnLCBgVG90YWwgUkFNOiAke3JhbX1NQmAsICdpbmZvJyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKFxuICAgICAgJ2luaXRpYWxpemUnLFxuICAgICAgYENvdWxkIG5vdCBjaGVjayB0b3RhbCBSQU0gZHVlIHRvOiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICk7XG4gIH1cblxuICAvLyBTYXZlIFdhenVoIEFwcCBzZXR1cFxuICBjb25zdCBzYXZlQ29uZmlndXJhdGlvbiA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29tbW9uRGF0ZSA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcblxuICAgICAgY29uc3QgY29uZmlndXJhdGlvbiA9IHtcbiAgICAgICAgbmFtZTogJ1dhenVoIEFwcCcsXG4gICAgICAgICdhcHAtdmVyc2lvbic6IHBhY2thZ2VKU09OLnZlcnNpb24sXG4gICAgICAgIHJldmlzaW9uOiBwYWNrYWdlSlNPTi5yZXZpc2lvbixcbiAgICAgICAgaW5zdGFsbGF0aW9uRGF0ZTogY29tbW9uRGF0ZSxcbiAgICAgICAgbGFzdFJlc3RhcnQ6IGNvbW1vbkRhdGUsXG4gICAgICAgIGhvc3RzOiB7fVxuICAgICAgfTtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoJ2NvbmZpZycpO1xuICAgICAgICBhd2FpdCBmcy53cml0ZUZpbGVTeW5jKFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEgsIEpTT04uc3RyaW5naWZ5KGNvbmZpZ3VyYXRpb24pLCAndXRmOCcpO1xuICAgICAgICBsb2coXG4gICAgICAgICAgJ2luaXRpYWxpemU6c2F2ZUNvbmZpZ3VyYXRpb24nLFxuICAgICAgICAgICdXYXp1aCBjb25maWd1cmF0aW9uIHJlZ2lzdHJ5IGluc2VydGVkJyxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBsb2coJ2luaXRpYWxpemU6c2F2ZUNvbmZpZ3VyYXRpb24nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgJ0NvdWxkIG5vdCBjcmVhdGUgV2F6dWggY29uZmlndXJhdGlvbiByZWdpc3RyeSdcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdpbml0aWFsaXplOnNhdmVDb25maWd1cmF0aW9uJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ0Vycm9yIGNyZWF0aW5nIHdhenVoLXZlcnNpb24gcmVnaXN0cnknXG4gICAgICApO1xuICAgIH1cbiAgfTtcblxuICAvKipcbiAgICogQ2hlY2tzIGlmIHRoZSAud2F6dWggaW5kZXggZXhpc3QgaW4gb3JkZXIgdG8gbWlncmF0ZSB0byB3YXp1aC55bWxcbiAgICovXG4gIGNvbnN0IGNoZWNrV2F6dWhJbmRleCA9IHRyeUNhdGNoRm9ySW5kZXhQZXJtaXNzaW9uRXJyb3IoV0FaVUhfSU5ERVgpKCBhc3luYyAoKSA9PiB7XG4gICAgbG9nKCdpbml0aWFsaXplOmNoZWNrV2F6dWhJbmRleCcsIGBDaGVja2luZyAke1dBWlVIX0lOREVYfSBpbmRleC5gLCAnZGVidWcnKTtcbiAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgaW5kZXg6IFdBWlVIX0lOREVYXG4gICAgfSk7XG4gICAgaWYgKHJlc3VsdC5ib2R5KSB7XG4gICAgICBjb25zdCBkYXRhID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLnNlYXJjaCh7XG4gICAgICAgIGluZGV4OiBXQVpVSF9JTkRFWCxcbiAgICAgICAgc2l6ZTogMTAwXG4gICAgICB9KTtcbiAgICAgIGNvbnN0IGFwaUVudHJpZXMgPSAoKChkYXRhIHx8IHt9KS5ib2R5IHx8IHt9KS5oaXRzIHx8IHt9KS5oaXRzIHx8IFtdO1xuICAgICAgYXdhaXQgbWFuYWdlSG9zdHMubWlncmF0ZUZyb21JbmRleChhcGlFbnRyaWVzKTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ2luaXRpYWxpemU6Y2hlY2tXYXp1aEluZGV4JyxcbiAgICAgICAgYEluZGV4ICR7V0FaVUhfSU5ERVh9IHdpbGwgYmUgcmVtb3ZlZCBhbmQgaXRzIGNvbnRlbnQgd2lsbCBiZSBtaWdyYXRlZCB0byB3YXp1aC55bWxgLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgLy8gQ2hlY2sgaWYgYWxsIEFQSXMgZW50cmllcyB3ZXJlIG1pZ3JhdGVkIHByb3Blcmx5IGFuZCBkZWxldGUgaXQgZnJvbSB0aGUgLndhenVoIGluZGV4XG4gICAgICBhd2FpdCBjaGVja1Byb3Blcmx5TWlncmF0ZSgpO1xuICAgICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZGVsZXRlKHtcbiAgICAgICAgaW5kZXg6IFdBWlVIX0lOREVYXG4gICAgICB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8qKlxuICAgKiBDaGVja3MgaWYgdGhlIEFQSSBlbnRyaWVzIHdlcmUgcHJvcGVybHkgbWlncmF0ZWRcbiAgICogQHBhcmFtIHtBcnJheX0gbWlncmF0ZWRBcGlzXG4gICAqL1xuICBjb25zdCBjaGVja1Byb3Blcmx5TWlncmF0ZSA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgbGV0IGFwaXNJbmRleCA9IGF3YWl0IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5zZWFyY2goe1xuICAgICAgICBpbmRleDogV0FaVUhfSU5ERVgsXG4gICAgICAgIHNpemU6IDEwMFxuICAgICAgfSk7XG4gICAgICBjb25zdCBob3N0cyA9IGF3YWl0IG1hbmFnZUhvc3RzLmdldEhvc3RzKCk7XG4gICAgICBhcGlzSW5kZXggPSAoKGFwaXNJbmRleC5ib2R5IHx8IHt9KS5oaXRzIHx8IHt9KS5oaXRzIHx8IFtdO1xuXG4gICAgICBjb25zdCBhcGlzSW5kZXhLZXlzID0gYXBpc0luZGV4Lm1hcChhcGkgPT4ge1xuICAgICAgICByZXR1cm4gYXBpLl9pZDtcbiAgICAgIH0pO1xuICAgICAgY29uc3QgaG9zdHNLZXlzID0gaG9zdHMubWFwKGFwaSA9PiB7XG4gICAgICAgIHJldHVybiBPYmplY3Qua2V5cyhhcGkpWzBdO1xuICAgICAgfSk7XG5cbiAgICAgIC8vIEdldCBpbnRvIGFuIGFycmF5IHRoZSBBUEkgZW50cmllcyB0aGF0IHdlcmUgbm90IG1pZ3JhdGVkLCBpZiB0aGUgbGVuZ3RoIGlzIDAgdGhlbiBhbGwgdGhlIEFQSSBlbnRyaWVzIHdlcmUgcHJvcGVybHkgbWlncmF0ZWQuXG4gICAgICBjb25zdCByZXN0ID0gYXBpc0luZGV4S2V5cy5maWx0ZXIoayA9PiB7XG4gICAgICAgIHJldHVybiAhaG9zdHNLZXlzLmluY2x1ZGVzKGspO1xuICAgICAgfSk7XG5cbiAgICAgIGlmIChyZXN0Lmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgYENhbm5vdCBtaWdyYXRlIGFsbCBBUEkgZW50cmllcywgbWlzc2VkIGVudHJpZXM6ICgke3Jlc3QudG9TdHJpbmcoKX0pYFxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgbG9nKFxuICAgICAgICAnaW5pdGlhbGl6ZTpjaGVja1Byb3Blcmx5TWlncmF0ZScsXG4gICAgICAgICdUaGUgQVBJIGVudHJpZXMgbWlncmF0aW9uIHdhcyBzdWNjZXNzZnVsJyxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdpbml0aWFsaXplOmNoZWNrUHJvcGVybHlNaWdyYXRlJywgYCR7ZXJyb3J9YCwgJ2Vycm9yJyk7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfTtcblxuICAvKipcbiAgICogQ2hlY2tzIGlmIHRoZSAud2F6dWgtdmVyc2lvbiBleGlzdHMsIGluIHRoaXMgY2FzZSBpdCB3aWxsIGJlIGRlbGV0ZWQgYW5kIHRoZSB3YXp1aC1yZWdpc3RyeS5qc29uIHdpbGwgYmUgY3JlYXRlZFxuICAgKi9cbiAgY29uc3QgY2hlY2tXYXp1aFJlZ2lzdHJ5ID0gYXN5bmMgKCkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coXG4gICAgICAgICdpbml0aWFsaXplOmNoZWNrd2F6dWhSZWdpc3RyeScsXG4gICAgICAgICdDaGVja2luZyB3YXp1aC12ZXJzaW9uIHJlZ2lzdHJ5LicsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICB0cnkge1xuICAgICAgIGNvbnN0IGV4aXN0cyA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgICAgaW5kZXg6IFdBWlVIX1ZFUlNJT05fSU5ERVhcbiAgICAgICAgfSk7ICAgICAgICBcbiAgICAgICAgaWYgKGV4aXN0cy5ib2R5KXtcbiAgICAgICAgICBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5kZWxldGUoe1xuICAgICAgICAgICAgaW5kZXg6IFdBWlVIX1ZFUlNJT05fSU5ERVhcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBsb2coXG4gICAgICAgICAgICAnaW5pdGlhbGl6ZVtjaGVja3dhenVoUmVnaXN0cnldJyxcbiAgICAgICAgICAgIGBTdWNjZXNzZnVsbHkgZGVsZXRlZCBvbGQgJHtXQVpVSF9WRVJTSU9OX0lOREVYfSBpbmRleC5gLFxuICAgICAgICAgICAgJ2RlYnVnJ1xuICAgICAgICAgICk7XG4gICAgICAgIH07XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBsb2coXG4gICAgICAgICAgJ2luaXRpYWxpemVbY2hlY2t3YXp1aFJlZ2lzdHJ5XScsXG4gICAgICAgICAgYE5vIG5lZWQgdG8gZGVsZXRlIG9sZCAke1dBWlVIX1ZFUlNJT05fSU5ERVh9IGluZGV4YCxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGlmKCFmcy5leGlzdHNTeW5jKFdBWlVIX0RBVEFfS0lCQU5BX0JBU0VfQUJTT0xVVEVfUEFUSCkpe1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYFRoZSBkYXRhIGRpcmVjdG9yeSBpcyBtaXNzaW5nIGluIHRoZSBLaWJhbmEgcm9vdCBpbnN0YWxhdGlvbi4gQ3JlYXRlIHRoZSBkaXJlY3RvcnkgaW4gJHtXQVpVSF9EQVRBX0tJQkFOQV9CQVNFX0FCU09MVVRFX1BBVEh9IGFuZCBnaXZlIGl0IHRoZSByZXF1aXJlZCBwZXJtaXNzaW9ucyAoc3VkbyBta2RpciAke1dBWlVIX0RBVEFfS0lCQU5BX0JBU0VfQUJTT0xVVEVfUEFUSH07c3VkbyBjaG93biAtUiBraWJhbmE6a2liYW5hICR7V0FaVUhfREFUQV9LSUJBTkFfQkFTRV9BQlNPTFVURV9QQVRIfSkuIEFmdGVyIHJlc3RhcnQgdGhlIEtpYmFuYSBzZXJ2aWNlLmApO1xuICAgICAgfTtcblxuICAgICAgaWYgKCFmcy5leGlzdHNTeW5jKFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEgpKSB7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAnaW5pdGlhbGl6ZTpjaGVja3dhenVoUmVnaXN0cnknLFxuICAgICAgICAgICd3YXp1aC12ZXJzaW9uIHJlZ2lzdHJ5IGRvZXMgbm90IGV4aXN0LiBJbml0aWFsaXppbmcgY29uZmlndXJhdGlvbi4nLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcblxuICAgICAgICAvLyBDcmVhdGUgdGhlIGFwcCByZWdpc3RyeSBmaWxlIGZvciB0aGUgdmVyeSBmaXJzdCB0aW1lXG4gICAgICAgIGF3YWl0IHNhdmVDb25maWd1cmF0aW9uKCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBJZiB0aGlzIGZ1bmN0aW9uIGZhaWxzLCBpdCB0aHJvd3MgYW4gZXhjZXB0aW9uXG4gICAgICAgIGNvbnN0IHNvdXJjZSA9IEpTT04ucGFyc2UoZnMucmVhZEZpbGVTeW5jKFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEgsICd1dGY4JykpO1xuXG4gICAgICAgIC8vIENoZWNrIGlmIHRoZSBzdG9yZWQgcmV2aXNpb24gZGlmZmVycyBmcm9tIHRoZSBwYWNrYWdlLmpzb24gcmV2aXNpb25cbiAgICAgICAgY29uc3QgaXNVcGdyYWRlZEFwcCA9IHBhY2thZ2VKU09OLnJldmlzaW9uICE9PSBzb3VyY2UucmV2aXNpb24gfHwgcGFja2FnZUpTT04udmVyc2lvbiAhPT0gc291cmNlWydhcHAtdmVyc2lvbiddO1xuXG4gICAgICAgIC8vIFJlYnVpbGQgdGhlIHJlZ2lzdHJ5IGZpbGUgaWYgcmV2aXNpb24gb3IgdmVyc2lvbiBmaWVsZHMgYXJlIGRpZmZlcmVudHNcbiAgICAgICAgaWYgKGlzVXBncmFkZWRBcHApIHsgXG4gICAgICAgICAgbG9nKFxuICAgICAgICAgICAgJ2luaXRpYWxpemU6Y2hlY2t3YXp1aFJlZ2lzdHJ5JyxcbiAgICAgICAgICAgICdXYXp1aCBhcHAgcmV2aXNpb24gb3IgdmVyc2lvbiBjaGFuZ2VkLCByZWdlbmVyYXRpbmcgd2F6dWgtdmVyc2lvbiByZWdpc3RyeScsXG4gICAgICAgICAgICAnaW5mbydcbiAgICAgICAgICApO1xuICAgICAgICAgIC8vIFJlYnVpbGQgcmVnaXN0cnkgZmlsZSBpbiBibGFua1xuICAgICAgICAgIGF3YWl0IHNhdmVDb25maWd1cmF0aW9uKCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH07XG5cbiAgLy8gSW5pdCBmdW5jdGlvbi4gQ2hlY2sgZm9yIFwid2F6dWgtdmVyc2lvblwiIGRvY3VtZW50IGV4aXN0YW5jZS5cbiAgY29uc3QgaW5pdCA9IGFzeW5jICgpID0+IHtcbiAgICBhd2FpdCBQcm9taXNlLmFsbChbXG4gICAgICBjaGVja1dhenVoSW5kZXgoKSxcbiAgICAgIGNoZWNrV2F6dWhSZWdpc3RyeSgpXG4gICAgXSk7XG4gIH07XG5cbiAgY29uc3QgY3JlYXRlS2liYW5hVGVtcGxhdGUgPSAoKSA9PiB7XG4gICAgbG9nKFxuICAgICAgJ2luaXRpYWxpemU6Y3JlYXRlS2liYW5hVGVtcGxhdGUnLFxuICAgICAgYENyZWF0aW5nIHRlbXBsYXRlIGZvciAke0tJQkFOQV9JTkRFWH1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICB0cnkge1xuICAgICAga2liYW5hVGVtcGxhdGUudGVtcGxhdGUgPSBLSUJBTkFfSU5ERVggKyAnKic7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnaW5pdGlhbGl6ZTpjcmVhdGVLaWJhbmFUZW1wbGF0ZScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoXG4gICAgICAgICdFeGNlcHRpb246ICcgKyBlcnJvci5tZXNzYWdlIHx8IGVycm9yXG4gICAgICApO1xuICAgIH1cblxuICAgIHJldHVybiBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5wdXRUZW1wbGF0ZSh7XG4gICAgICBuYW1lOiBXQVpVSF9LSUJBTkFfVEVNUExBVEVfTkFNRSxcbiAgICAgIG9yZGVyOiAwLFxuICAgICAgY3JlYXRlOiB0cnVlLFxuICAgICAgYm9keToga2liYW5hVGVtcGxhdGVcbiAgICB9KTtcbiAgfTtcblxuICBjb25zdCBjcmVhdGVFbXB0eUtpYmFuYUluZGV4ID0gYXN5bmMgKCkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coXG4gICAgICAgICdpbml0aWFsaXplOmNyZWF0ZUVtcHR5S2liYW5hSW5kZXgnLFxuICAgICAgICBgQ3JlYXRpbmcgJHtLSUJBTkFfSU5ERVh9IGluZGV4LmAsXG4gICAgICAgICdpbmZvJ1xuICAgICAgKTtcbiAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLmNyZWF0ZSh7XG4gICAgICAgIGluZGV4OiBLSUJBTkFfSU5ERVhcbiAgICAgIH0pO1xuICAgICAgbG9nKFxuICAgICAgICAnaW5pdGlhbGl6ZTpjcmVhdGVFbXB0eUtpYmFuYUluZGV4JyxcbiAgICAgICAgYFN1Y2Nlc3NmdWxseSBjcmVhdGVkICR7S0lCQU5BX0lOREVYfSBpbmRleC5gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgYXdhaXQgaW5pdCgpO1xuICAgICAgcmV0dXJuO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgIG5ldyBFcnJvcihcbiAgICAgICAgICBgRXJyb3IgY3JlYXRpbmcgJHtcbiAgICAgICAgICBLSUJBTkFfSU5ERVhcbiAgICAgICAgICB9IGluZGV4IGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICAgICApXG4gICAgICApO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCBmaXhLaWJhbmFUZW1wbGF0ZSA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgY3JlYXRlS2liYW5hVGVtcGxhdGUoKTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ2luaXRpYWxpemU6Y2hlY2tLaWJhbmFTdGF0dXMnLFxuICAgICAgICBgU3VjY2Vzc2Z1bGx5IGNyZWF0ZWQgJHtLSUJBTkFfSU5ERVh9IHRlbXBsYXRlLmAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBhd2FpdCBjcmVhdGVFbXB0eUtpYmFuYUluZGV4KCk7XG4gICAgICByZXR1cm47XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcbiAgICAgICAgbmV3IEVycm9yKFxuICAgICAgICAgIGBFcnJvciBjcmVhdGluZyB0ZW1wbGF0ZSBmb3IgJHtcbiAgICAgICAgICBLSUJBTkFfSU5ERVhcbiAgICAgICAgICB9IGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICAgICApXG4gICAgICApO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCBnZXRUZW1wbGF0ZUJ5TmFtZSA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZ2V0VGVtcGxhdGUoe1xuICAgICAgICBuYW1lOiBXQVpVSF9LSUJBTkFfVEVNUExBVEVfTkFNRVxuICAgICAgfSk7XG4gICAgICBsb2coXG4gICAgICAgICdpbml0aWFsaXplOmNoZWNrS2liYW5hU3RhdHVzJyxcbiAgICAgICAgYE5vIG5lZWQgdG8gY3JlYXRlIHRoZSAke0tJQkFOQV9JTkRFWH0gdGVtcGxhdGUsIGFscmVhZHkgZXhpc3RzLmAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBhd2FpdCBjcmVhdGVFbXB0eUtpYmFuYUluZGV4KCk7XG4gICAgICByZXR1cm47XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnaW5pdGlhbGl6ZTpjaGVja0tpYmFuYVN0YXR1cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIGZpeEtpYmFuYVRlbXBsYXRlKCk7XG4gICAgfVxuICB9O1xuXG4gIC8vIERvZXMgS2liYW5hIGluZGV4IGV4aXN0P1xuICBjb25zdCBjaGVja0tpYmFuYVN0YXR1cyA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgICBpbmRleDogS0lCQU5BX0lOREVYXG4gICAgICB9KTtcbiAgICAgIGlmIChyZXNwb25zZS5ib2R5KSB7XG4gICAgICAgIC8vIEl0IGV4aXN0cywgaW5pdGlhbGl6ZSFcbiAgICAgICAgYXdhaXQgaW5pdCgpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gTm8gS2liYW5hIGluZGV4IGNyZWF0ZWQuLi5cbiAgICAgICAgbG9nKFxuICAgICAgICAgICdpbml0aWFsaXplOmNoZWNrS2liYW5hU3RhdHVzJyxcbiAgICAgICAgICBgTm90IGZvdW5kICR7S0lCQU5BX0lOREVYfSBpbmRleGAsXG4gICAgICAgICAgJ2luZm8nXG4gICAgICAgICk7XG4gICAgICAgIGF3YWl0IGdldFRlbXBsYXRlQnlOYW1lKCk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnaW5pdGlhbGl6ZTpjaGVja0tpYmFuYVN0YXR1cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgfVxuICB9O1xuXG4gIC8vIFdhaXQgdW50aWwgRWxhc3RpY3NlYXJjaCBqcyBpcyByZWFkeVxuICBjb25zdCBjaGVja1N0YXR1cyA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgLy8gVE9ETzogd2FpdCB1bnRpbCBlbGFzdGljc2VhcmNoIGlzIHJlYWR5P1xuICAgICAgLy8gYXdhaXQgc2VydmVyLnBsdWdpbnMuZWxhc3RpY3NlYXJjaC53YWl0VW50aWxSZWFkeSgpO1xuICAgICAgcmV0dXJuIGF3YWl0IGNoZWNrS2liYW5hU3RhdHVzKCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ2luaXRpYWxpemU6Y2hlY2tTdGF0dXMnLFxuICAgICAgICAnV2FpdGluZyBmb3IgZWxhc3RpY3NlYXJjaCBwbHVnaW4gdG8gYmUgcmVhZHkuLi4nLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgc2V0VGltZW91dCgoKSA9PiBjaGVja1N0YXR1cygpLCAzMDAwKTtcbiAgICB9XG4gIH07XG5cbiAgLy8gQ2hlY2sgS2liYW5hIGluZGV4IGFuZCBpZiBpdCBpcyBwcmVwYXJlZCwgc3RhcnQgdGhlIGluaXRpYWxpemF0aW9uIG9mIFdhenVoIEFwcC5cbiAgcmV0dXJuIGNoZWNrU3RhdHVzKCk7XG59XG4iXX0=