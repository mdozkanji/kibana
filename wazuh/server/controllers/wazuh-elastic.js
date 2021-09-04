"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhElasticCtrl = void 0;

var _errorResponse = require("../lib/error-response");

var _logger = require("../lib/logger");

var _getConfiguration = require("../lib/get-configuration");

var _visualizations = require("../integration-files/visualizations");

var _generateAlertsScript = require("../lib/generate-alerts/generate-alerts-script");

var _constants = require("../../common/constants");

var _jwtDecode = _interopRequireDefault(require("jwt-decode"));

var _manageHosts = require("../lib/manage-hosts");

var _cookie = require("../lib/cookie");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class WazuhElasticCtrl {
  constructor() {
    _defineProperty(this, "wzSampleAlertsIndexPrefix", void 0);

    _defineProperty(this, "manageHosts", void 0);

    this.wzSampleAlertsIndexPrefix = this.getSampleAlertPrefix();
    this.manageHosts = new _manageHosts.ManageHosts();
  }
  /**
   * This returns the index according the category
   * @param {string} category
   */


  buildSampleIndexByCategory(category) {
    return `${this.wzSampleAlertsIndexPrefix}sample-${category}`;
  }
  /**
   * This returns the defined config for sample alerts prefix or the default value.
   */


  getSampleAlertPrefix() {
    const config = (0, _getConfiguration.getConfiguration)();
    return config['alerts.sample.prefix'] || _constants.WAZUH_SAMPLE_ALERT_PREFIX;
  }
  /**
   * This retrieves a template from Elasticsearch
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} template or ErrorResponse
   */


  async getTemplate(context, request, response) {
    try {
      const data = await context.core.elasticsearch.client.asInternalUser.cat.templates();
      const templates = data.body;

      if (!templates || typeof templates !== 'string') {
        throw new Error('An unknown error occurred when fetching templates from Elasticseach');
      }

      const lastChar = request.params.pattern[request.params.pattern.length - 1]; // Split into separate patterns

      const tmpdata = templates.match(/\[.*\]/g);
      const tmparray = [];

      for (let item of tmpdata) {
        // A template might use more than one pattern
        if (item.includes(',')) {
          item = item.substr(1).slice(0, -1);
          const subItems = item.split(',');

          for (const subitem of subItems) {
            tmparray.push(`[${subitem.trim()}]`);
          }
        } else {
          tmparray.push(item);
        }
      } // Ensure we are handling just patterns


      const array = tmparray.filter(item => item.includes('[') && item.includes(']'));
      const pattern = lastChar === '*' ? request.params.pattern.slice(0, -1) : request.params.pattern;
      const isIncluded = array.filter(item => {
        item = item.slice(1, -1);
        const lastChar = item[item.length - 1];
        item = lastChar === '*' ? item.slice(0, -1) : item;
        return item.includes(pattern) || pattern.includes(item);
      });
      (0, _logger.log)('wazuh-elastic:getTemplate', `Template is valid: ${isIncluded && Array.isArray(isIncluded) && isIncluded.length ? 'yes' : 'no'}`, 'debug');
      return isIncluded && Array.isArray(isIncluded) && isIncluded.length ? response.ok({
        body: {
          statusCode: 200,
          status: true,
          data: `Template found for ${request.params.pattern}`
        }
      }) : response.ok({
        body: {
          statusCode: 200,
          status: false,
          data: `No template found for ${request.params.pattern}`
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getTemplate', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Could not retrieve templates from Elasticsearch due to ${error.message || error}`, 4002, 500, response);
    }
  }
  /**
   * This check index-pattern
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async checkPattern(context, request, response) {
    try {
      const data = await context.core.savedObjects.client.find({
        type: 'index-pattern'
      });
      const existsIndexPattern = data.saved_objects.find(item => item.attributes.title === request.params.pattern);
      (0, _logger.log)('wazuh-elastic:checkPattern', `Index pattern found: ${existsIndexPattern ? existsIndexPattern.attributes.title : 'no'}`, 'debug');
      return existsIndexPattern ? response.ok({
        body: {
          statusCode: 200,
          status: true,
          data: 'Index pattern found'
        }
      }) : response.ok({
        body: {
          statusCode: 500,
          status: false,
          error: 10020,
          message: 'Index pattern not found'
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:checkPattern', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Something went wrong retrieving index-patterns from Elasticsearch due to ${error.message || error}`, 4003, 500, response);
    }
  }
  /**
   * This get the fields keys
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Array<Object>} fields or ErrorResponse
   */


  async getFieldTop(context, request, response) {
    try {
      // Top field payload
      let payload = {
        size: 1,
        query: {
          bool: {
            must: [],
            must_not: {
              term: {
                'agent.id': '000'
              }
            },
            filter: [{
              range: {
                timestamp: {}
              }
            }]
          }
        },
        aggs: {
          '2': {
            terms: {
              field: '',
              size: 1,
              order: {
                _count: 'desc'
              }
            }
          }
        }
      }; // Set up time interval, default to Last 24h

      const timeGTE = 'now-1d';
      const timeLT = 'now';
      payload.query.bool.filter[0].range['timestamp']['gte'] = timeGTE;
      payload.query.bool.filter[0].range['timestamp']['lt'] = timeLT; // Set up match for default cluster name

      payload.query.bool.must.push(request.params.mode === 'cluster' ? {
        match: {
          'cluster.name': request.params.cluster
        }
      } : {
        match: {
          'manager.name': request.params.cluster
        }
      });
      if (request.query.agentsList) payload.query.bool.filter.push({
        terms: {
          'agent.id': request.query.agentsList.split(',')
        }
      });
      payload.aggs['2'].terms.field = request.params.field;
      const data = await context.core.elasticsearch.client.asCurrentUser.search({
        size: 1,
        index: request.params.pattern,
        body: payload
      });
      return data.body.hits.total.value === 0 || typeof data.body.aggregations['2'].buckets[0] === 'undefined' ? response.ok({
        body: {
          statusCode: 200,
          data: ''
        }
      }) : response.ok({
        body: {
          statusCode: 200,
          data: data.body.aggregations['2'].buckets[0].key
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getFieldTop', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4004, 500, response);
    }
  }
  /**
   * Checks one by one if the requesting user has enough privileges to use
   * an index pattern from the list.
   * @param {Array<Object>} list List of index patterns
   * @param {Object} req
   * @returns {Array<Object>} List of allowed index
   */


  async filterAllowedIndexPatternList(context, list, req) {
    //TODO: review if necesary to delete
    let finalList = [];

    for (let item of list) {
      let results = false,
          forbidden = false;

      try {
        results = await context.core.elasticsearch.client.asCurrentUser.search({
          index: item.title
        });
      } catch (error) {
        forbidden = true;
      }

      if ((((results || {}).body || {}).hits || {}).total.value >= 1 || !forbidden && (((results || {}).body || {}).hits || {}).total === 0) {
        finalList.push(item);
      }
    }

    return finalList;
  }
  /**
   * Checks for minimum index pattern fields in a list of index patterns.
   * @param {Array<Object>} indexPatternList List of index patterns
   */


  validateIndexPattern(indexPatternList) {
    const minimum = ['timestamp', 'rule.groups', 'manager.name', 'agent.id'];
    let list = [];

    for (const index of indexPatternList) {
      let valid, parsed;

      try {
        parsed = JSON.parse(index.attributes.fields);
      } catch (error) {
        continue;
      }

      valid = parsed.filter(item => minimum.includes(item.name));

      if (valid.length === 4) {
        list.push({
          id: index.id,
          title: index.attributes.title
        });
      }
    }

    return list;
  }
  /**
   * Returns current security platform
   * @param {Object} req
   * @param {Object} reply
   * @returns {String}
   */


  async getCurrentPlatform(context, request, response) {
    try {
      return response.ok({
        body: {
          platform: context.wazuh.security.platform
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getCurrentPlatform', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4011, 500, response);
    }
  }
  /**
   * Replaces visualizations main fields to fit a certain pattern.
   * @param {Array<Object>} app_objects Object containing raw visualizations.
   * @param {String} id Index-pattern id to use in the visualizations. Eg: 'wazuh-alerts'
   */


  async buildVisualizationsRaw(app_objects, id, namespace = false) {
    try {
      const config = (0, _getConfiguration.getConfiguration)();
      let monitoringPattern = (config || {})['wazuh.monitoring.pattern'] || _constants.WAZUH_MONITORING_PATTERN;
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', `Building ${app_objects.length} visualizations`, 'debug');
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', `Index pattern ID: ${id}`, 'debug');
      const visArray = [];
      let aux_source, bulk_content;

      for (let element of app_objects) {
        aux_source = JSON.parse(JSON.stringify(element._source)); // Replace index-pattern for visualizations

        if (aux_source && aux_source.kibanaSavedObjectMeta && aux_source.kibanaSavedObjectMeta.searchSourceJSON && typeof aux_source.kibanaSavedObjectMeta.searchSourceJSON === 'string') {
          const defaultStr = aux_source.kibanaSavedObjectMeta.searchSourceJSON;
          const isMonitoring = defaultStr.includes('wazuh-monitoring');

          if (isMonitoring) {
            if (namespace && namespace !== 'default') {
              if (monitoringPattern.includes(namespace) && monitoringPattern.includes('index-pattern:')) {
                monitoringPattern = monitoringPattern.split('index-pattern:')[1];
              }
            }

            aux_source.kibanaSavedObjectMeta.searchSourceJSON = defaultStr.replace(/wazuh-monitoring/g, monitoringPattern[monitoringPattern.length - 1] === '*' || namespace && namespace !== 'default' ? monitoringPattern : monitoringPattern + '*');
          } else {
            aux_source.kibanaSavedObjectMeta.searchSourceJSON = defaultStr.replace(/wazuh-alerts/g, id);
          }
        } // Replace index-pattern for selector visualizations


        if (typeof (aux_source || {}).visState === 'string') {
          aux_source.visState = aux_source.visState.replace(/wazuh-alerts/g, id);
        } // Bulk source


        bulk_content = {};
        bulk_content[element._type] = aux_source;
        visArray.push({
          attributes: bulk_content.visualization,
          type: element._type,
          id: element._id,
          _version: bulk_content.visualization.version
        });
      }

      return visArray;
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Replaces cluster visualizations main fields.
   * @param {Array<Object>} app_objects Object containing raw visualizations.
   * @param {String} id Index-pattern id to use in the visualizations. Eg: 'wazuh-alerts'
   * @param {Array<String>} nodes Array of node names. Eg: ['node01', 'node02']
   * @param {String} name Cluster name. Eg: 'wazuh'
   * @param {String} master_node Master node name. Eg: 'node01'
   */


  buildClusterVisualizationsRaw(app_objects, id, nodes = [], name, master_node, pattern_name = '*') {
    try {
      const visArray = [];
      let aux_source, bulk_content;

      for (const element of app_objects) {
        // Stringify and replace index-pattern for visualizations
        aux_source = JSON.stringify(element._source);
        aux_source = aux_source.replace(/wazuh-alerts/g, id);
        aux_source = JSON.parse(aux_source); // Bulk source

        bulk_content = {};
        bulk_content[element._type] = aux_source;
        const visState = JSON.parse(bulk_content.visualization.visState);
        const title = visState.title;

        if (visState.type && visState.type === 'timelion') {
          let query = '';

          if (title === 'Wazuh App Cluster Overview') {
            for (const node of nodes) {
              query += `.es(index=${pattern_name},q="cluster.name: ${name} AND cluster.node: ${node.name}").label("${node.name}"),`;
            }

            query = query.substring(0, query.length - 1);
          } else if (title === 'Wazuh App Cluster Overview Manager') {
            query += `.es(index=${pattern_name},q="cluster.name: ${name}").label("${name} cluster")`;
          } else {
            if (title.startsWith('Wazuh App Statistics')) {
              const {
                searchSourceJSON
              } = bulk_content.visualization.kibanaSavedObjectMeta;
              bulk_content.visualization.kibanaSavedObjectMeta.searchSourceJSON = searchSourceJSON.replace('wazuh-statistics-*', pattern_name);
            }

            if (title.startsWith('Wazuh App Statistics') && name !== '-' && name !== 'all' && visState.params.expression.includes('q=')) {
              const expressionRegex = /q='\*'/gi;

              const _visState = bulk_content.visualization.visStateByNode ? JSON.parse(bulk_content.visualization.visStateByNode) : visState;

              query += _visState.params.expression.replace(/wazuh-statistics-\*/g, pattern_name).replace(expressionRegex, `q="nodeName.keyword:${name} AND apiName.keyword:${master_node}"`).replace("NODE_NAME", name);
            } else if (title.startsWith('Wazuh App Statistics')) {
              const expressionRegex = /q='\*'/gi;
              query += visState.params.expression.replace(/wazuh-statistics-\*/g, pattern_name).replace(expressionRegex, `q="apiName.keyword:${master_node}"`);
            } else {
              query = visState.params.expression;
            }
          }

          visState.params.expression = query.replace(/'/g, "\"");
          bulk_content.visualization.visState = JSON.stringify(visState);
        }

        visArray.push({
          attributes: bulk_content.visualization,
          type: element._type,
          id: element._id,
          _version: bulk_content.visualization.version
        });
      }

      return visArray;
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:buildClusterVisualizationsRaw', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * This creates a visualization of data in req
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} vis obj or ErrorResponse
   */


  async createVis(context, request, response) {
    try {
      if (!request.params.tab.includes('overview-') && !request.params.tab.includes('agents-')) {
        throw new Error('Missing parameters creating visualizations');
      }

      const tabPrefix = request.params.tab.includes('overview') ? 'overview' : 'agents';
      const tabSplit = request.params.tab.split('-');
      const tabSufix = tabSplit[1];
      const file = tabPrefix === 'overview' ? _visualizations.OverviewVisualizations[tabSufix] : _visualizations.AgentsVisualizations[tabSufix];
      (0, _logger.log)('wazuh-elastic:createVis', `${tabPrefix}[${tabSufix}] with index pattern ${request.params.pattern}`, 'debug');
      const namespace = context.wazuh.plugins.spaces && context.wazuh.plugins.spaces.spacesService && context.wazuh.plugins.spaces.spacesService.getSpaceId(request);
      const raw = await this.buildVisualizationsRaw(file, request.params.pattern, namespace);
      return response.ok({
        body: {
          acknowledge: true,
          raw: raw
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createVis', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4007, 500, response);
    }
  }
  /**
   * This creates a visualization of cluster
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} vis obj or ErrorResponse
   */


  async createClusterVis(context, request, response) {
    try {
      if (!request.params.pattern || !request.params.tab || !request.body || !request.body.nodes || !request.body.nodes.affected_items || !request.body.nodes.name || request.params.tab && !request.params.tab.includes('cluster-')) {
        throw new Error('Missing parameters creating visualizations');
      }

      const type = request.params.tab.split('-')[1];
      const file = _visualizations.ClusterVisualizations[type];
      const nodes = request.body.nodes.affected_items;
      const name = request.body.nodes.name;
      const masterNode = request.body.nodes.master_node;
      const {
        id: patternID,
        title: patternName
      } = request.body.pattern;
      const raw = await this.buildClusterVisualizationsRaw(file, patternID, nodes, name, masterNode, patternName);
      return response.ok({
        body: {
          acknowledge: true,
          raw: raw
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createClusterVis', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4009, 500, response);
    }
  }
  /**
   * This checks if there is sample alerts
   * GET /elastic/samplealerts
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {alerts: [...]} or ErrorResponse
   */


  async haveSampleAlerts(context, request, response) {
    try {
      // Check if wazuh sample alerts index exists
      const results = await Promise.all(Object.keys(_constants.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS).map(category => context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: this.buildSampleIndexByCategory(category)
      })));
      return response.ok({
        body: {
          sampleAlertsInstalled: results.some(result => result.body)
        }
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)('Sample Alerts category not valid', 1000, 500, response);
    }
  }
  /**
   * This creates sample alerts in wazuh-sample-alerts
   * GET /elastic/samplealerts/{category}
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {alerts: [...]} or ErrorResponse
   */


  async haveSampleAlertsOfCategory(context, request, response) {
    try {
      const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category); // Check if wazuh sample alerts index exists

      const existsSampleIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });
      return response.ok({
        body: {
          index: sampleAlertsIndex,
          exists: existsSampleIndex.body
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:haveSampleAlertsOfCategory', `Error checking if there are sample alerts indices: ${error.message || error}`);
      return (0, _errorResponse.ErrorResponse)(`Error checking if there are sample alerts indices: ${error.message || error}`, 1000, 500, response);
    }
  }
  /**
   * This creates sample alerts in wazuh-sample-alerts
   * POST /elastic/samplealerts/{category}
   * {
   *   "manager": {
   *      "name": "manager_name"
   *    },
   *    cluster: {
   *      name: "mycluster",
   *      node: "mynode"
   *    }
   * }
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {index: string, alerts: [...], count: number} or ErrorResponse
   */


  async createSampleAlerts(context, request, response) {
    const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category);

    try {
      // Check if user has administrator role in token
      const token = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

      if (!token) {
        return (0, _errorResponse.ErrorResponse)('No token provided', 401, 401, response);
      }

      ;
      const decodedToken = (0, _jwtDecode.default)(token);

      if (!decodedToken) {
        return (0, _errorResponse.ErrorResponse)('No permissions in token', 401, 401, response);
      }

      ;

      if (!decodedToken.rbac_roles || !decodedToken.rbac_roles.includes(_constants.WAZUH_ROLE_ADMINISTRATOR_ID)) {
        return (0, _errorResponse.ErrorResponse)('No administrator role', 401, 401, response);
      }

      ; // Check the provided token is valid

      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!apiHostID) {
        return (0, _errorResponse.ErrorResponse)('No API id provided', 401, 401, response);
      }

      ;
      const responseTokenIsWorking = await context.wazuh.api.client.asCurrentUser.request('GET', `//`, {}, {
        apiHostID
      });

      if (responseTokenIsWorking.status !== 200) {
        return (0, _errorResponse.ErrorResponse)('Token is not valid', 500, 500, response);
      }

      ;
      const bulkPrefix = JSON.stringify({
        index: {
          _index: sampleAlertsIndex
        }
      });
      const alertGenerateParams = request.body && request.body.params || {};

      const sampleAlerts = _constants.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS[request.params.category].map(typeAlert => (0, _generateAlertsScript.generateAlerts)({ ...typeAlert,
        ...alertGenerateParams
      }, request.body.alerts || typeAlert.alerts || _constants.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS)).flat();

      const bulk = sampleAlerts.map(sampleAlert => `${bulkPrefix}\n${JSON.stringify(sampleAlert)}\n`).join(''); // Index alerts
      // Check if wazuh sample alerts index exists

      const existsSampleIndex = await context.core.elasticsearch.client.asInternalUser.indices.exists({
        index: sampleAlertsIndex
      });

      if (!existsSampleIndex.body) {
        // Create wazuh sample alerts index
        const configuration = {
          settings: {
            index: {
              number_of_shards: _constants.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS,
              number_of_replicas: _constants.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS
            }
          }
        };
        await context.core.elasticsearch.client.asInternalUser.indices.create({
          index: sampleAlertsIndex,
          body: configuration
        });
        (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Created ${sampleAlertsIndex} index`, 'debug');
      }

      await context.core.elasticsearch.client.asInternalUser.bulk({
        index: sampleAlertsIndex,
        body: bulk
      });
      (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Added sample alerts to ${sampleAlertsIndex} index`, 'debug');
      return response.ok({
        body: {
          index: sampleAlertsIndex,
          alertCount: sampleAlerts.length
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Error adding sample alerts to ${sampleAlertsIndex} index: ${error.message || error}`);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 1000, 500, response);
    }
  }
  /**
   * This deletes sample alerts
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {result: "deleted", index: string} or ErrorResponse
   */


  async deleteSampleAlerts(context, request, response) {
    // Delete Wazuh sample alert index
    const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category);

    try {
      // Check if user has administrator role in token
      const token = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

      if (!token) {
        return (0, _errorResponse.ErrorResponse)('No token provided', 401, 401, response);
      }

      ;
      const decodedToken = (0, _jwtDecode.default)(token);

      if (!decodedToken) {
        return (0, _errorResponse.ErrorResponse)('No permissions in token', 401, 401, response);
      }

      ;

      if (!decodedToken.rbac_roles || !decodedToken.rbac_roles.includes(_constants.WAZUH_ROLE_ADMINISTRATOR_ID)) {
        return (0, _errorResponse.ErrorResponse)('No administrator role', 401, 401, response);
      }

      ; // Check the provided token is valid

      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!apiHostID) {
        return (0, _errorResponse.ErrorResponse)('No API id provided', 401, 401, response);
      }

      ;
      const responseTokenIsWorking = await context.wazuh.api.client.asCurrentUser.request('GET', `//`, {}, {
        apiHostID
      });

      if (responseTokenIsWorking.status !== 200) {
        return (0, _errorResponse.ErrorResponse)('Token is not valid', 500, 500, response);
      }

      ; // Check if Wazuh sample alerts index exists

      const existsSampleIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });

      if (existsSampleIndex.body) {
        // Delete Wazuh sample alerts index
        await context.core.elasticsearch.client.asCurrentUser.indices.delete({
          index: sampleAlertsIndex
        });
        (0, _logger.log)('wazuh-elastic:deleteSampleAlerts', `Deleted ${sampleAlertsIndex} index`, 'debug');
        return response.ok({
          body: {
            result: 'deleted',
            index: sampleAlertsIndex
          }
        });
      } else {
        return (0, _errorResponse.ErrorResponse)(`${sampleAlertsIndex} index doesn't exist`, 1000, 500, response);
      }
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:deleteSampleAlerts', `Error deleting sample alerts of ${sampleAlertsIndex} index: ${error.message || error}`);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 1000, 500, response);
    }
  }

  async alerts(context, request, response) {
    try {
      const data = await context.core.elasticsearch.client.asCurrentUser.search(request.body);
      return response.ok({
        body: data.body
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:alerts', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4010, 500, response);
    }
  } // Check if there are indices for Statistics


  async existStatisticsIndices(context, request, response) {
    try {
      const config = (0, _getConfiguration.getConfiguration)();
      const statisticsPattern = `${config['cron.prefix'] || 'wazuh'}-${config['cron.statistics.index.name'] || 'statistics'}*`; //TODO: replace by default as constants instead hardcoded ('wazuh' and 'statistics')

      const existIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: statisticsPattern,
        allow_no_indices: false
      });
      return response.ok({
        body: existIndex.body
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:existsStatisticsIndices', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 1000, 500, response);
    }
  }

  async usingCredentials(context) {
    try {
      const data = await context.core.elasticsearch.client.asInternalUser.cluster.getSettings({
        include_defaults: true
      });
      return (((((data || {}).body || {}).defaults || {}).xpack || {}).security || {}).user !== null;
    } catch (error) {
      return Promise.reject(error);
    }
  }

}

exports.WazuhElasticCtrl = WazuhElasticCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWVsYXN0aWMudHMiXSwibmFtZXMiOlsiV2F6dWhFbGFzdGljQ3RybCIsImNvbnN0cnVjdG9yIiwid3pTYW1wbGVBbGVydHNJbmRleFByZWZpeCIsImdldFNhbXBsZUFsZXJ0UHJlZml4IiwibWFuYWdlSG9zdHMiLCJNYW5hZ2VIb3N0cyIsImJ1aWxkU2FtcGxlSW5kZXhCeUNhdGVnb3J5IiwiY2F0ZWdvcnkiLCJjb25maWciLCJXQVpVSF9TQU1QTEVfQUxFUlRfUFJFRklYIiwiZ2V0VGVtcGxhdGUiLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiZGF0YSIsImNvcmUiLCJlbGFzdGljc2VhcmNoIiwiY2xpZW50IiwiYXNJbnRlcm5hbFVzZXIiLCJjYXQiLCJ0ZW1wbGF0ZXMiLCJib2R5IiwiRXJyb3IiLCJsYXN0Q2hhciIsInBhcmFtcyIsInBhdHRlcm4iLCJsZW5ndGgiLCJ0bXBkYXRhIiwibWF0Y2giLCJ0bXBhcnJheSIsIml0ZW0iLCJpbmNsdWRlcyIsInN1YnN0ciIsInNsaWNlIiwic3ViSXRlbXMiLCJzcGxpdCIsInN1Yml0ZW0iLCJwdXNoIiwidHJpbSIsImFycmF5IiwiZmlsdGVyIiwiaXNJbmNsdWRlZCIsIkFycmF5IiwiaXNBcnJheSIsIm9rIiwic3RhdHVzQ29kZSIsInN0YXR1cyIsImVycm9yIiwibWVzc2FnZSIsImNoZWNrUGF0dGVybiIsInNhdmVkT2JqZWN0cyIsImZpbmQiLCJ0eXBlIiwiZXhpc3RzSW5kZXhQYXR0ZXJuIiwic2F2ZWRfb2JqZWN0cyIsImF0dHJpYnV0ZXMiLCJ0aXRsZSIsImdldEZpZWxkVG9wIiwicGF5bG9hZCIsInNpemUiLCJxdWVyeSIsImJvb2wiLCJtdXN0IiwibXVzdF9ub3QiLCJ0ZXJtIiwicmFuZ2UiLCJ0aW1lc3RhbXAiLCJhZ2dzIiwidGVybXMiLCJmaWVsZCIsIm9yZGVyIiwiX2NvdW50IiwidGltZUdURSIsInRpbWVMVCIsIm1vZGUiLCJjbHVzdGVyIiwiYWdlbnRzTGlzdCIsImFzQ3VycmVudFVzZXIiLCJzZWFyY2giLCJpbmRleCIsImhpdHMiLCJ0b3RhbCIsInZhbHVlIiwiYWdncmVnYXRpb25zIiwiYnVja2V0cyIsImtleSIsImZpbHRlckFsbG93ZWRJbmRleFBhdHRlcm5MaXN0IiwibGlzdCIsInJlcSIsImZpbmFsTGlzdCIsInJlc3VsdHMiLCJmb3JiaWRkZW4iLCJ2YWxpZGF0ZUluZGV4UGF0dGVybiIsImluZGV4UGF0dGVybkxpc3QiLCJtaW5pbXVtIiwidmFsaWQiLCJwYXJzZWQiLCJKU09OIiwicGFyc2UiLCJmaWVsZHMiLCJuYW1lIiwiaWQiLCJnZXRDdXJyZW50UGxhdGZvcm0iLCJwbGF0Zm9ybSIsIndhenVoIiwic2VjdXJpdHkiLCJidWlsZFZpc3VhbGl6YXRpb25zUmF3IiwiYXBwX29iamVjdHMiLCJuYW1lc3BhY2UiLCJtb25pdG9yaW5nUGF0dGVybiIsIldBWlVIX01PTklUT1JJTkdfUEFUVEVSTiIsInZpc0FycmF5IiwiYXV4X3NvdXJjZSIsImJ1bGtfY29udGVudCIsImVsZW1lbnQiLCJzdHJpbmdpZnkiLCJfc291cmNlIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImRlZmF1bHRTdHIiLCJpc01vbml0b3JpbmciLCJyZXBsYWNlIiwidmlzU3RhdGUiLCJfdHlwZSIsInZpc3VhbGl6YXRpb24iLCJfaWQiLCJfdmVyc2lvbiIsInZlcnNpb24iLCJQcm9taXNlIiwicmVqZWN0IiwiYnVpbGRDbHVzdGVyVmlzdWFsaXphdGlvbnNSYXciLCJub2RlcyIsIm1hc3Rlcl9ub2RlIiwicGF0dGVybl9uYW1lIiwibm9kZSIsInN1YnN0cmluZyIsInN0YXJ0c1dpdGgiLCJleHByZXNzaW9uIiwiZXhwcmVzc2lvblJlZ2V4IiwiX3Zpc1N0YXRlIiwidmlzU3RhdGVCeU5vZGUiLCJjcmVhdGVWaXMiLCJ0YWIiLCJ0YWJQcmVmaXgiLCJ0YWJTcGxpdCIsInRhYlN1Zml4IiwiZmlsZSIsIk92ZXJ2aWV3VmlzdWFsaXphdGlvbnMiLCJBZ2VudHNWaXN1YWxpemF0aW9ucyIsInBsdWdpbnMiLCJzcGFjZXMiLCJzcGFjZXNTZXJ2aWNlIiwiZ2V0U3BhY2VJZCIsInJhdyIsImFja25vd2xlZGdlIiwiY3JlYXRlQ2x1c3RlclZpcyIsImFmZmVjdGVkX2l0ZW1zIiwiQ2x1c3RlclZpc3VhbGl6YXRpb25zIiwibWFzdGVyTm9kZSIsInBhdHRlcm5JRCIsInBhdHRlcm5OYW1lIiwiaGF2ZVNhbXBsZUFsZXJ0cyIsImFsbCIsIk9iamVjdCIsImtleXMiLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JJRVNfVFlQRV9BTEVSVFMiLCJtYXAiLCJpbmRpY2VzIiwiZXhpc3RzIiwic2FtcGxlQWxlcnRzSW5zdGFsbGVkIiwic29tZSIsInJlc3VsdCIsImhhdmVTYW1wbGVBbGVydHNPZkNhdGVnb3J5Iiwic2FtcGxlQWxlcnRzSW5kZXgiLCJleGlzdHNTYW1wbGVJbmRleCIsImNyZWF0ZVNhbXBsZUFsZXJ0cyIsInRva2VuIiwiaGVhZGVycyIsImNvb2tpZSIsImRlY29kZWRUb2tlbiIsInJiYWNfcm9sZXMiLCJXQVpVSF9ST0xFX0FETUlOSVNUUkFUT1JfSUQiLCJhcGlIb3N0SUQiLCJyZXNwb25zZVRva2VuSXNXb3JraW5nIiwiYXBpIiwiYnVsa1ByZWZpeCIsIl9pbmRleCIsImFsZXJ0R2VuZXJhdGVQYXJhbXMiLCJzYW1wbGVBbGVydHMiLCJ0eXBlQWxlcnQiLCJhbGVydHMiLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0RFRkFVTFRfTlVNQkVSX0FMRVJUUyIsImZsYXQiLCJidWxrIiwic2FtcGxlQWxlcnQiLCJqb2luIiwiY29uZmlndXJhdGlvbiIsInNldHRpbmdzIiwibnVtYmVyX29mX3NoYXJkcyIsIldBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfU0hBUkRTIiwibnVtYmVyX29mX3JlcGxpY2FzIiwiV0FaVUhfU0FNUExFX0FMRVJUU19JTkRFWF9SRVBMSUNBUyIsImNyZWF0ZSIsImFsZXJ0Q291bnQiLCJkZWxldGVTYW1wbGVBbGVydHMiLCJkZWxldGUiLCJleGlzdFN0YXRpc3RpY3NJbmRpY2VzIiwic3RhdGlzdGljc1BhdHRlcm4iLCJleGlzdEluZGV4IiwiYWxsb3dfbm9faW5kaWNlcyIsInVzaW5nQ3JlZGVudGlhbHMiLCJnZXRTZXR0aW5ncyIsImluY2x1ZGVfZGVmYXVsdHMiLCJkZWZhdWx0cyIsInhwYWNrIiwidXNlciJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQVdBOztBQUNBOztBQUNBOztBQUNBOztBQU1BOztBQUNBOztBQUNBOztBQUNBOztBQUVBOzs7Ozs7QUFHTyxNQUFNQSxnQkFBTixDQUF1QjtBQUc1QkMsRUFBQUEsV0FBVyxHQUFHO0FBQUE7O0FBQUE7O0FBQ1osU0FBS0MseUJBQUwsR0FBaUMsS0FBS0Msb0JBQUwsRUFBakM7QUFDQSxTQUFLQyxXQUFMLEdBQW1CLElBQUlDLHdCQUFKLEVBQW5CO0FBQ0Q7QUFFRDs7Ozs7O0FBSUFDLEVBQUFBLDBCQUEwQixDQUFDQyxRQUFELEVBQTJCO0FBQ25ELFdBQVEsR0FBRSxLQUFLTCx5QkFBMEIsVUFBU0ssUUFBUyxFQUEzRDtBQUNEO0FBRUQ7Ozs7O0FBR0FKLEVBQUFBLG9CQUFvQixHQUFXO0FBQzdCLFVBQU1LLE1BQU0sR0FBRyx5Q0FBZjtBQUNBLFdBQU9BLE1BQU0sQ0FBQyxzQkFBRCxDQUFOLElBQWtDQyxvQ0FBekM7QUFDRDtBQUVEOzs7Ozs7Ozs7QUFPQSxRQUFNQyxXQUFOLENBQWtCQyxPQUFsQixFQUFrREMsT0FBbEQsRUFBK0ZDLFFBQS9GLEVBQWdJO0FBQzlILFFBQUk7QUFDRixZQUFNQyxJQUFJLEdBQUcsTUFBTUgsT0FBTyxDQUFDSSxJQUFSLENBQWFDLGFBQWIsQ0FBMkJDLE1BQTNCLENBQWtDQyxjQUFsQyxDQUFpREMsR0FBakQsQ0FBcURDLFNBQXJELEVBQW5CO0FBRUEsWUFBTUEsU0FBUyxHQUFHTixJQUFJLENBQUNPLElBQXZCOztBQUNBLFVBQUksQ0FBQ0QsU0FBRCxJQUFjLE9BQU9BLFNBQVAsS0FBcUIsUUFBdkMsRUFBaUQ7QUFDL0MsY0FBTSxJQUFJRSxL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QixRQUFJO0FBQ0YsWUFBTUcsSUFBSSxHQUFHLE1BQU1ILE9BQU8sQ0FBQ0ksSUFBUixDQUFhQyxhQUFiLENBQTJCQyxNQUEzQixDQUFrQ0MsY0FBbEMsQ0FBaUR5RCxPQUFqRCxDQUF5RHdJLFdBQXpELENBQ2pCO0FBQUVDLFFBQUFBLGdCQUFnQixFQUFFO0FBQXBCLE9BRGlCLENBQW5CO0FBR0EsYUFBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUN0TSxJQUFJLElBQUksRUFBVCxFQUFhTyxJQUFiLElBQXFCLEVBQXRCLEVBQTBCZ00sUUFBMUIsSUFBc0MsRUFBdkMsRUFBMkNDLEtBQTNDLElBQW9ELEVBQXJELEVBQXlEN0csUUFBekQsSUFBcUUsRUFBdEUsRUFBMEU4RyxJQUExRSxLQUFtRixJQUExRjtBQUNELEtBTEQsQ0FLRSxPQUFPeEssS0FBUCxFQUFjO0FBQ2QsYUFBT2lGLE9BQU8sQ0FBQ0MsTUFBUixDQUFlbEYsS0FBZixDQUFQO0FBQ0Q7QUFDRjs7QUF2ekIyQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBDbGFzcyBmb3IgV2F6dWgtRWxhc3RpYyBmdW5jdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIxIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5pbXBvcnQgeyBFcnJvclJlc3BvbnNlIH0gZnJvbSAnLi4vbGliL2Vycm9yLXJlc3BvbnNlJztcbmltcG9ydCB7IGxvZyB9IGZyb20gJy4uL2xpYi9sb2dnZXInO1xuaW1wb3J0IHsgZ2V0Q29uZmlndXJhdGlvbiB9IGZyb20gJy4uL2xpYi9nZXQtY29uZmlndXJhdGlvbic7XG5pbXBvcnQge1xuICBBZ2VudHNWaXN1YWxpemF0aW9ucyxcbiAgT3ZlcnZpZXdWaXN1YWxpemF0aW9ucyxcbiAgQ2x1c3RlclZpc3VhbGl6YXRpb25zXG59IGZyb20gJy4uL2ludGVncmF0aW9uLWZpbGVzL3Zpc3VhbGl6YXRpb25zJztcblxuaW1wb3J0IHsgZ2VuZXJhdGVBbGVydHMgfSBmcm9tICcuLi9saWIvZ2VuZXJhdGUtYWxlcnRzL2dlbmVyYXRlLWFsZXJ0cy1zY3JpcHQnO1xuaW1wb3J0IHsgV0FaVUhfTU9OSVRPUklOR19QQVRURVJOLCBXQVpVSF9TQU1QTEVfQUxFUlRfUFJFRklYLCBXQVpVSF9ST0xFX0FETUlOSVNUUkFUT1JfSUQsIFdBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfU0hBUkRTLCBXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1JFUExJQ0FTIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgand0RGVjb2RlIGZyb20gJ2p3dC1kZWNvZGUnO1xuaW1wb3J0IHsgTWFuYWdlSG9zdHMgfSBmcm9tICcuLi9saWIvbWFuYWdlLWhvc3RzJztcbmltcG9ydCB7IEtpYmFuYVJlcXVlc3QsIFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgS2liYW5hUmVzcG9uc2VGYWN0b3J5LCBTYXZlZE9iamVjdCwgU2F2ZWRPYmplY3RzRmluZFJlc3BvbnNlIH0gZnJvbSAnc3JjL2NvcmUvc2VydmVyJztcbmltcG9ydCB7IGdldENvb2tpZVZhbHVlQnlOYW1lIH0gZnJvbSAnLi4vbGliL2Nvb2tpZSc7XG5pbXBvcnQgeyBXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JJRVNfVFlQRV9BTEVSVFMsIFdBWlVIX1NBTVBMRV9BTEVSVFNfREVGQVVMVF9OVU1CRVJfQUxFUlRTIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcblxuZXhwb3J0IGNsYXNzIFdhenVoRWxhc3RpY0N0cmwge1xuICB3elNhbXBsZUFsZXJ0c0luZGV4UHJlZml4OiBzdHJpbmdcbiAgbWFuYWdlSG9zdHM6IE1hbmFnZUhvc3RzXG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHRoaXMud3pTYW1wbGVBbGVydHNJbmRleFByZWZpeCA9IHRoaXMuZ2V0U2FtcGxlQWxlcnRQcmVmaXgoKTtcbiAgICB0aGlzLm1hbmFnZUhvc3RzID0gbmV3IE1hbmFnZUhvc3RzKCk7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyByZXR1cm5zIHRoZSBpbmRleCBhY2NvcmRpbmcgdGhlIGNhdGVnb3J5XG4gICAqIEBwYXJhbSB7c3RyaW5nfSBjYXRlZ29yeVxuICAgKi9cbiAgYnVpbGRTYW1wbGVJbmRleEJ5Q2F0ZWdvcnkoY2F0ZWdvcnk6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGAke3RoaXMud3pTYW1wbGVBbGVydHNJbmRleFByZWZpeH1zYW1wbGUtJHtjYXRlZ29yeX1gO1xuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgcmV0dXJucyB0aGUgZGVmaW5lZCBjb25maWcgZm9yIHNhbXBsZSBhbGVydHMgcHJlZml4IG9yIHRoZSBkZWZhdWx0IHZhbHVlLlxuICAgKi9cbiAgZ2V0U2FtcGxlQWxlcnRQcmVmaXgoKTogc3RyaW5nIHtcbiAgICBjb25zdCBjb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgcmV0dXJuIGNvbmZpZ1snYWxlcnRzLnNhbXBsZS5wcmVmaXgnXSB8fCBXQVpVSF9TQU1QTEVfQUxFUlRfUFJFRklYO1xuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgcmV0cmlldmVzIGEgdGVtcGxhdGUgZnJvbSBFbGFzdGljc2VhcmNoXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSB0ZW1wbGF0ZSBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBnZXRUZW1wbGF0ZShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3Q8eyBwYXR0ZXJuOiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5jYXQudGVtcGxhdGVzKCk7XG5cbiAgICAgIGNvbnN0IHRlbXBsYXRlcyA9IGRhdGEuYm9keTtcbiAgICAgIGlmICghdGVtcGxhdGVzIHx8IHR5cGVvZiB0ZW1wbGF0ZXMgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAnQW4gdW5rbm93biBlcnJvciBvY2N1cnJlZCB3aGVuIGZldGNoaW5nIHRlbXBsYXRlcyBmcm9tIEVsYXN0aWNzZWFjaCdcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgbGFzdENoYXIgPSByZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuW3JlcXVlc3QucGFyYW1zLnBhdHRlcm4ubGVuZ3RoIC0gMV07XG5cbiAgICAgIC8vIFNwbGl0IGludG8gc2VwYXJhdGUgcGF0dGVybnNcbiAgICAgIGNvbnN0IHRtcGRhdGEgPSB0ZW1wbGF0ZXMubWF0Y2goL1xcWy4qXFxdL2cpO1xuICAgICAgY29uc3QgdG1wYXJyYXkgPSBbXTtcbiAgICAgIGZvciAobGV0IGl0ZW0gb2YgdG1wZGF0YSkge1xuICAgICAgICAvLyBBIHRlbXBsYXRlIG1pZ2h0IHVzZSBtb3JlIHRoYW4gb25lIHBhdHRlcm5cbiAgICAgICAgaWYgKGl0ZW0uaW5jbHVkZXMoJywnKSkge1xuICAgICAgICAgIGl0ZW0gPSBpdGVtLnN1YnN0cigxKS5zbGljZSgwLCAtMSk7XG4gICAgICAgICAgY29uc3Qgc3ViSXRlbXMgPSBpdGVtLnNwbGl0KCcsJyk7XG4gICAgICAgICAgZm9yIChjb25zdCBzdWJpdGVtIG9mIHN1Ykl0ZW1zKSB7XG4gICAgICAgICAgICB0bXBhcnJheS5wdXNoKGBbJHtzdWJpdGVtLnRyaW0oKX1dYCk7XG4gICAgICAgICAgfVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRtcGFycmF5LnB1c2goaXRlbSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy8gRW5zdXJlIHdlIGFyZSBoYW5kbGluZyBqdXN0IHBhdHRlcm5zXG4gICAgICBjb25zdCBhcnJheSA9IHRtcGFycmF5LmZpbHRlcihcbiAgICAgICAgaXRlbSA9PiBpdGVtLmluY2x1ZGVzKCdbJykgJiYgaXRlbS5pbmNsdWRlcygnXScpXG4gICAgICApO1xuXG4gICAgICBjb25zdCBwYXR0ZXJuID1cbiAgICAgICAgbGFzdENoYXIgPT09ICcqJyA/IHJlcXVlc3QucGFyYW1zLnBhdHRlcm4uc2xpY2UoMCwgLTEpIDogcmVxdWVzdC5wYXJhbXMucGF0dGVybjtcbiAgICAgIGNvbnN0IGlzSW5jbHVkZWQgPSBhcnJheS5maWx0ZXIoaXRlbSA9PiB7XG4gICAgICAgIGl0ZW0gPSBpdGVtLnNsaWNlKDEsIC0xKTtcbiAgICAgICAgY29uc3QgbGFzdENoYXIgPSBpdGVtW2l0ZW0ubGVuZ3RoIC0gMV07XG4gICAgICAgIGl0ZW0gPSBsYXN0Q2hhciA9PT0gJyonID8gaXRlbS5zbGljZSgwLCAtMSkgOiBpdGVtO1xuICAgICAgICByZXR1cm4gaXRlbS5pbmNsdWRlcyhwYXR0ZXJuKSB8fCBwYXR0ZXJuLmluY2x1ZGVzKGl0ZW0pO1xuICAgICAgfSk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmdldFRlbXBsYXRlJyxcbiAgICAgICAgYFRlbXBsYXRlIGlzIHZhbGlkOiAke2lzSW5jbHVkZWQgJiYgQXJyYXkuaXNBcnJheShpc0luY2x1ZGVkKSAmJiBpc0luY2x1ZGVkLmxlbmd0aFxuICAgICAgICAgID8gJ3llcydcbiAgICAgICAgICA6ICdubydcbiAgICAgICAgfWAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gaXNJbmNsdWRlZCAmJiBBcnJheS5pc0FycmF5KGlzSW5jbHVkZWQpICYmIGlzSW5jbHVkZWQubGVuZ3RoXG4gICAgICAgID8gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICAgIHN0YXR1czogdHJ1ZSxcbiAgICAgICAgICAgIGRhdGE6IGBUZW1wbGF0ZSBmb3VuZCBmb3IgJHtyZXF1ZXN0LnBhcmFtcy5wYXR0ZXJufWBcbiAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgIDogcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICAgIHN0YXR1czogZmFsc2UsXG4gICAgICAgICAgICBkYXRhOiBgTm8gdGVtcGxhdGUgZm91bmQgZm9yICR7cmVxdWVzdC5wYXJhbXMucGF0dGVybn1gXG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmdldFRlbXBsYXRlJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgYENvdWxkIG5vdCByZXRyaWV2ZSB0ZW1wbGF0ZXMgZnJvbSBFbGFzdGljc2VhcmNoIGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHxcbiAgICAgICAgZXJyb3J9YCxcbiAgICAgICAgNDAwMixcbiAgICAgICAgNTAwLFxuICAgICAgICByZXNwb25zZVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBjaGVjayBpbmRleC1wYXR0ZXJuXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBzdGF0dXMgb2JqIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNoZWNrUGF0dGVybihjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3Q8eyBwYXR0ZXJuOiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5zYXZlZE9iamVjdHMuY2xpZW50LmZpbmQ8U2F2ZWRPYmplY3RzRmluZFJlc3BvbnNlPFNhdmVkT2JqZWN0Pj4oeyB0eXBlOiAnaW5kZXgtcGF0dGVybicgfSk7XG5cbiAgICAgIGNvbnN0IGV4aXN0c0luZGV4UGF0dGVybiA9IGRhdGEuc2F2ZWRfb2JqZWN0cy5maW5kKFxuICAgICAgICBpdGVtID0+IGl0ZW0uYXR0cmlidXRlcy50aXRsZSA9PT0gcmVxdWVzdC5wYXJhbXMucGF0dGVyblxuICAgICAgKTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3dhenVoLWVsYXN0aWM6Y2hlY2tQYXR0ZXJuJyxcbiAgICAgICAgYEluZGV4IHBhdHRlcm4gZm91bmQ6ICR7ZXhpc3RzSW5kZXhQYXR0ZXJuID8gZXhpc3RzSW5kZXhQYXR0ZXJuLmF0dHJpYnV0ZXMudGl0bGUgOiAnbm8nfWAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gZXhpc3RzSW5kZXhQYXR0ZXJuXG4gICAgICAgID8gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHsgc3RhdHVzQ29kZTogMjAwLCBzdGF0dXM6IHRydWUsIGRhdGE6ICdJbmRleCBwYXR0ZXJuIGZvdW5kJyB9XG4gICAgICAgIH0pXG4gICAgICAgIDogcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IDUwMCxcbiAgICAgICAgICAgIHN0YXR1czogZmFsc2UsXG4gICAgICAgICAgICBlcnJvcjogMTAwMjAsXG4gICAgICAgICAgICBtZXNzYWdlOiAnSW5kZXggcGF0dGVybiBub3QgZm91bmQnXG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmNoZWNrUGF0dGVybicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgIGBTb21ldGhpbmcgd2VudCB3cm9uZyByZXRyaWV2aW5nIGluZGV4LXBhdHRlcm5zIGZyb20gRWxhc3RpY3NlYXJjaCBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8XG4gICAgICAgIGVycm9yfWAsXG4gICAgICAgIDQwMDMsXG4gICAgICAgIDUwMCxcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgZ2V0IHRoZSBmaWVsZHMga2V5c1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge0FycmF5PE9iamVjdD59IGZpZWxkcyBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBnZXRGaWVsZFRvcChjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3Q8eyBtb2RlOiBzdHJpbmcsIGNsdXN0ZXI6IHN0cmluZywgZmllbGQ6IHN0cmluZywgcGF0dGVybjogc3RyaW5nIH0sIHsgYWdlbnRzTGlzdDogc3RyaW5nIH0+LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIC8vIFRvcCBmaWVsZCBwYXlsb2FkXG4gICAgICBsZXQgcGF5bG9hZCA9IHtcbiAgICAgICAgc2l6ZTogMSxcbiAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICBib29sOiB7XG4gICAgICAgICAgICBtdXN0OiBbXSxcbiAgICAgICAgICAgIG11c3Rfbm90OiB7XG4gICAgICAgICAgICAgIHRlcm06IHtcbiAgICAgICAgICAgICAgICAnYWdlbnQuaWQnOiAnMDAwJ1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZmlsdGVyOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByYW5nZTogeyB0aW1lc3RhbXA6IHt9IH1cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgXVxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgYWdnczoge1xuICAgICAgICAgICcyJzoge1xuICAgICAgICAgICAgdGVybXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICcnLFxuICAgICAgICAgICAgICBzaXplOiAxLFxuICAgICAgICAgICAgICBvcmRlcjogeyBfY291bnQ6ICdkZXNjJyB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuXG4gICAgICAvLyBTZXQgdXAgdGltZSBpbnRlcnZhbCwgZGVmYXVsdCB0byBMYXN0IDI0aFxuICAgICAgY29uc3QgdGltZUdURSA9ICdub3ctMWQnO1xuICAgICAgY29uc3QgdGltZUxUID0gJ25vdyc7XG4gICAgICBwYXlsb2FkLnF1ZXJ5LmJvb2wuZmlsdGVyWzBdLnJhbmdlWyd0aW1lc3RhbXAnXVsnZ3RlJ10gPSB0aW1lR1RFO1xuICAgICAgcGF5bG9hZC5xdWVyeS5ib29sLmZpbHRlclswXS5yYW5nZVsndGltZXN0YW1wJ11bJ2x0J10gPSB0aW1lTFQ7XG5cbiAgICAgIC8vIFNldCB1cCBtYXRjaCBmb3IgZGVmYXVsdCBjbHVzdGVyIG5hbWVcbiAgICAgIHBheWxvYWQucXVlcnkuYm9vbC5tdXN0LnB1c2goXG4gICAgICAgIHJlcXVlc3QucGFyYW1zLm1vZGUgPT09ICdjbHVzdGVyJ1xuICAgICAgICAgID8geyBtYXRjaDogeyAnY2x1c3Rlci5uYW1lJzogcmVxdWVzdC5wYXJhbXMuY2x1c3RlciB9IH1cbiAgICAgICAgICA6IHsgbWF0Y2g6IHsgJ21hbmFnZXIubmFtZSc6IHJlcXVlc3QucGFyYW1zLmNsdXN0ZXIgfSB9XG4gICAgICApO1xuXG4gICAgICBpZihyZXF1ZXN0LnF1ZXJ5LmFnZW50c0xpc3QpXG4gICAgICAgIHBheWxvYWQucXVlcnkuYm9vbC5maWx0ZXIucHVzaChcbiAgICAgICAgICB7XG4gICAgICAgICAgICB0ZXJtczoge1xuICAgICAgICAgICAgICAnYWdlbnQuaWQnOiByZXF1ZXN0LnF1ZXJ5LmFnZW50c0xpc3Quc3BsaXQoJywnKVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICAgIHBheWxvYWQuYWdnc1snMiddLnRlcm1zLmZpZWxkID0gcmVxdWVzdC5wYXJhbXMuZmllbGQ7XG5cbiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5zZWFyY2goe1xuICAgICAgICBzaXplOiAxLFxuICAgICAgICBpbmRleDogcmVxdWVzdC5wYXJhbXMucGF0dGVybixcbiAgICAgICAgYm9keTogcGF5bG9hZFxuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkYXRhLmJvZHkuaGl0cy50b3RhbC52YWx1ZSA9PT0gMCB8fFxuICAgICAgICB0eXBlb2YgZGF0YS5ib2R5LmFnZ3JlZ2F0aW9uc1snMiddLmJ1Y2tldHNbMF0gPT09ICd1bmRlZmluZWQnXG4gICAgICAgID8gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHsgc3RhdHVzQ29kZTogMjAwLCBkYXRhOiAnJyB9XG4gICAgICAgIH0pXG4gICAgICAgIDogcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICAgIGRhdGE6IGRhdGEuYm9keS5hZ2dyZWdhdGlvbnNbJzInXS5idWNrZXRzWzBdLmtleVxuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpnZXRGaWVsZFRvcCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNDAwNCwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrcyBvbmUgYnkgb25lIGlmIHRoZSByZXF1ZXN0aW5nIHVzZXIgaGFzIGVub3VnaCBwcml2aWxlZ2VzIHRvIHVzZVxuICAgKiBhbiBpbmRleCBwYXR0ZXJuIGZyb20gdGhlIGxpc3QuXG4gICAqIEBwYXJhbSB7QXJyYXk8T2JqZWN0Pn0gbGlzdCBMaXN0IG9mIGluZGV4IHBhdHRlcm5zXG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXFcbiAgICogQHJldHVybnMge0FycmF5PE9iamVjdD59IExpc3Qgb2YgYWxsb3dlZCBpbmRleFxuICAgKi9cbiAgYXN5bmMgZmlsdGVyQWxsb3dlZEluZGV4UGF0dGVybkxpc3QoY29udGV4dCwgbGlzdCwgcmVxKSB7XG4gICAgLy9UT0RPOiByZXZpZXcgaWYgbmVjZXNhcnkgdG8gZGVsZXRlXG4gICAgbGV0IGZpbmFsTGlzdCA9IFtdO1xuICAgIGZvciAobGV0IGl0ZW0gb2YgbGlzdCkge1xuICAgICAgbGV0IHJlc3VsdHMgPSBmYWxzZSxcbiAgICAgICAgZm9yYmlkZGVuID0gZmFsc2U7XG4gICAgICB0cnkge1xuICAgICAgICByZXN1bHRzID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuc2VhcmNoKHtcbiAgICAgICAgICBpbmRleDogaXRlbS50aXRsZVxuICAgICAgICB9KTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGZvcmJpZGRlbiA9IHRydWU7XG4gICAgICB9XG4gICAgICBpZiAoXG4gICAgICAgICgoKHJlc3VsdHMgfHwge30pLmJvZHkgfHwge30pLmhpdHMgfHwge30pLnRvdGFsLnZhbHVlID49IDEgfHxcbiAgICAgICAgKCFmb3JiaWRkZW4gJiYgKCgocmVzdWx0cyB8fCB7fSkuYm9keSB8fCB7fSkuaGl0cyB8fCB7fSkudG90YWwgPT09IDApXG4gICAgICApIHtcbiAgICAgICAgZmluYWxMaXN0LnB1c2goaXRlbSk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBmaW5hbExpc3Q7XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2tzIGZvciBtaW5pbXVtIGluZGV4IHBhdHRlcm4gZmllbGRzIGluIGEgbGlzdCBvZiBpbmRleCBwYXR0ZXJucy5cbiAgICogQHBhcmFtIHtBcnJheTxPYmplY3Q+fSBpbmRleFBhdHRlcm5MaXN0IExpc3Qgb2YgaW5kZXggcGF0dGVybnNcbiAgICovXG4gIHZhbGlkYXRlSW5kZXhQYXR0ZXJuKGluZGV4UGF0dGVybkxpc3QpIHtcbiAgICBjb25zdCBtaW5pbXVtID0gWyd0aW1lc3RhbXAnLCAncnVsZS5ncm91cHMnLCAnbWFuYWdlci5uYW1lJywgJ2FnZW50LmlkJ107XG4gICAgbGV0IGxpc3QgPSBbXTtcbiAgICBmb3IgKGNvbnN0IGluZGV4IG9mIGluZGV4UGF0dGVybkxpc3QpIHtcbiAgICAgIGxldCB2YWxpZCwgcGFyc2VkO1xuICAgICAgdHJ5IHtcbiAgICAgICAgcGFyc2VkID0gSlNPTi5wYXJzZShpbmRleC5hdHRyaWJ1dGVzLmZpZWxkcyk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgdmFsaWQgPSBwYXJzZWQuZmlsdGVyKGl0ZW0gPT4gbWluaW11bS5pbmNsdWRlcyhpdGVtLm5hbWUpKTtcbiAgICAgIGlmICh2YWxpZC5sZW5ndGggPT09IDQpIHtcbiAgICAgICAgbGlzdC5wdXNoKHtcbiAgICAgICAgICBpZDogaW5kZXguaWQsXG4gICAgICAgICAgdGl0bGU6IGluZGV4LmF0dHJpYnV0ZXMudGl0bGVcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBsaXN0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgY3VycmVudCBzZWN1cml0eSBwbGF0Zm9ybVxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxXG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXBseVxuICAgKiBAcmV0dXJucyB7U3RyaW5nfVxuICAgKi9cbiAgYXN5bmMgZ2V0Q3VycmVudFBsYXRmb3JtKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdDx7IHVzZXI6IHN0cmluZyB9PiwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7XG4gICAgICAgICAgcGxhdGZvcm06IGNvbnRleHQud2F6dWguc2VjdXJpdHkucGxhdGZvcm1cbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpnZXRDdXJyZW50UGxhdGZvcm0nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDQwMTEsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXBsYWNlcyB2aXN1YWxpemF0aW9ucyBtYWluIGZpZWxkcyB0byBmaXQgYSBjZXJ0YWluIHBhdHRlcm4uXG4gICAqIEBwYXJhbSB7QXJyYXk8T2JqZWN0Pn0gYXBwX29iamVjdHMgT2JqZWN0IGNvbnRhaW5pbmcgcmF3IHZpc3VhbGl6YXRpb25zLlxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWQgSW5kZXgtcGF0dGVybiBpZCB0byB1c2UgaW4gdGhlIHZpc3VhbGl6YXRpb25zLiBFZzogJ3dhenVoLWFsZXJ0cydcbiAgICovXG4gIGFzeW5jIGJ1aWxkVmlzdWFsaXphdGlvbnNSYXcoYXBwX29iamVjdHMsIGlkLCBuYW1lc3BhY2UgPSBmYWxzZSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgICBsZXQgbW9uaXRvcmluZ1BhdHRlcm4gPVxuICAgICAgICAoY29uZmlnIHx8IHt9KVsnd2F6dWgubW9uaXRvcmluZy5wYXR0ZXJuJ10gfHwgV0FaVUhfTU9OSVRPUklOR19QQVRURVJOO1xuICAgICAgbG9nKFxuICAgICAgICAnd2F6dWgtZWxhc3RpYzpidWlsZFZpc3VhbGl6YXRpb25zUmF3JyxcbiAgICAgICAgYEJ1aWxkaW5nICR7YXBwX29iamVjdHMubGVuZ3RofSB2aXN1YWxpemF0aW9uc2AsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmJ1aWxkVmlzdWFsaXphdGlvbnNSYXcnLFxuICAgICAgICBgSW5kZXggcGF0dGVybiBJRDogJHtpZH1gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgY29uc3QgdmlzQXJyYXkgPSBbXTtcbiAgICAgIGxldCBhdXhfc291cmNlLCBidWxrX2NvbnRlbnQ7XG4gICAgICBmb3IgKGxldCBlbGVtZW50IG9mIGFwcF9vYmplY3RzKSB7XG4gICAgICAgIGF1eF9zb3VyY2UgPSBKU09OLnBhcnNlKEpTT04uc3RyaW5naWZ5KGVsZW1lbnQuX3NvdXJjZSkpO1xuXG4gICAgICAgIC8vIFJlcGxhY2UgaW5kZXgtcGF0dGVybiBmb3IgdmlzdWFsaXphdGlvbnNcbiAgICAgICAgaWYgKFxuICAgICAgICAgIGF1eF9zb3VyY2UgJiZcbiAgICAgICAgICBhdXhfc291cmNlLmtpYmFuYVNhdmVkT2JqZWN0TWV0YSAmJlxuICAgICAgICAgIGF1eF9zb3VyY2Uua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT04gJiZcbiAgICAgICAgICB0eXBlb2YgYXV4X3NvdXJjZS5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTiA9PT0gJ3N0cmluZydcbiAgICAgICAgKSB7XG4gICAgICAgICAgY29uc3QgZGVmYXVsdFN0ciA9IGF1eF9zb3VyY2Uua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT047XG5cbiAgICAgICAgICBjb25zdCBpc01vbml0b3JpbmcgPSBkZWZhdWx0U3RyLmluY2x1ZGVzKCd3YXp1aC1tb25pdG9yaW5nJyk7XG4gICAgICAgICAgaWYgKGlzTW9uaXRvcmluZykge1xuICAgICAgICAgICAgaWYgKG5hbWVzcGFjZSAmJiBuYW1lc3BhY2UgIT09ICdkZWZhdWx0Jykge1xuICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgbW9uaXRvcmluZ1BhdHRlcm4uaW5jbHVkZXMobmFtZXNwYWNlKSAmJlxuICAgICAgICAgICAgICAgIG1vbml0b3JpbmdQYXR0ZXJuLmluY2x1ZGVzKCdpbmRleC1wYXR0ZXJuOicpXG4gICAgICAgICAgICAgICkge1xuICAgICAgICAgICAgICAgIG1vbml0b3JpbmdQYXR0ZXJuID0gbW9uaXRvcmluZ1BhdHRlcm4uc3BsaXQoXG4gICAgICAgICAgICAgICAgICAnaW5kZXgtcGF0dGVybjonXG4gICAgICAgICAgICAgICAgKVsxXTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYXV4X3NvdXJjZS5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTiA9IGRlZmF1bHRTdHIucmVwbGFjZShcbiAgICAgICAgICAgICAgL3dhenVoLW1vbml0b3JpbmcvZyxcbiAgICAgICAgICAgICAgbW9uaXRvcmluZ1BhdHRlcm5bbW9uaXRvcmluZ1BhdHRlcm4ubGVuZ3RoIC0gMV0gPT09ICcqJyB8fFxuICAgICAgICAgICAgICAgIChuYW1lc3BhY2UgJiYgbmFtZXNwYWNlICE9PSAnZGVmYXVsdCcpXG4gICAgICAgICAgICAgICAgPyBtb25pdG9yaW5nUGF0dGVyblxuICAgICAgICAgICAgICAgIDogbW9uaXRvcmluZ1BhdHRlcm4gKyAnKidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGF1eF9zb3VyY2Uua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT04gPSBkZWZhdWx0U3RyLnJlcGxhY2UoXG4gICAgICAgICAgICAgIC93YXp1aC1hbGVydHMvZyxcbiAgICAgICAgICAgICAgaWRcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gUmVwbGFjZSBpbmRleC1wYXR0ZXJuIGZvciBzZWxlY3RvciB2aXN1YWxpemF0aW9uc1xuICAgICAgICBpZiAodHlwZW9mIChhdXhfc291cmNlIHx8IHt9KS52aXNTdGF0ZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgICBhdXhfc291cmNlLnZpc1N0YXRlID0gYXV4X3NvdXJjZS52aXNTdGF0ZS5yZXBsYWNlKFxuICAgICAgICAgICAgL3dhenVoLWFsZXJ0cy9nLFxuICAgICAgICAgICAgaWRcbiAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQnVsayBzb3VyY2VcbiAgICAgICAgYnVsa19jb250ZW50ID0ge307XG4gICAgICAgIGJ1bGtfY29udGVudFtlbGVtZW50Ll90eXBlXSA9IGF1eF9zb3VyY2U7XG5cbiAgICAgICAgdmlzQXJyYXkucHVzaCh7XG4gICAgICAgICAgYXR0cmlidXRlczogYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24sXG4gICAgICAgICAgdHlwZTogZWxlbWVudC5fdHlwZSxcbiAgICAgICAgICBpZDogZWxlbWVudC5faWQsXG4gICAgICAgICAgX3ZlcnNpb246IGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLnZlcnNpb25cbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gdmlzQXJyYXk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpidWlsZFZpc3VhbGl6YXRpb25zUmF3JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXBsYWNlcyBjbHVzdGVyIHZpc3VhbGl6YXRpb25zIG1haW4gZmllbGRzLlxuICAgKiBAcGFyYW0ge0FycmF5PE9iamVjdD59IGFwcF9vYmplY3RzIE9iamVjdCBjb250YWluaW5nIHJhdyB2aXN1YWxpemF0aW9ucy5cbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkIEluZGV4LXBhdHRlcm4gaWQgdG8gdXNlIGluIHRoZSB2aXN1YWxpemF0aW9ucy4gRWc6ICd3YXp1aC1hbGVydHMnXG4gICAqIEBwYXJhbSB7QXJyYXk8U3RyaW5nPn0gbm9kZXMgQXJyYXkgb2Ygbm9kZSBuYW1lcy4gRWc6IFsnbm9kZTAxJywgJ25vZGUwMiddXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBuYW1lIENsdXN0ZXIgbmFtZS4gRWc6ICd3YXp1aCdcbiAgICogQHBhcmFtIHtTdHJpbmd9IG1hc3Rlcl9ub2RlIE1hc3RlciBub2RlIG5hbWUuIEVnOiAnbm9kZTAxJ1xuICAgKi9cbiAgYnVpbGRDbHVzdGVyVmlzdWFsaXphdGlvbnNSYXcoXG4gICAgYXBwX29iamVjdHMsXG4gICAgaWQsXG4gICAgbm9kZXMgPSBbXSxcbiAgICBuYW1lLFxuICAgIG1hc3Rlcl9ub2RlLFxuICAgIHBhdHRlcm5fbmFtZSA9ICcqJ1xuICApIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgdmlzQXJyYXkgPSBbXTtcbiAgICAgIGxldCBhdXhfc291cmNlLCBidWxrX2NvbnRlbnQ7XG5cbiAgICAgIGZvciAoY29uc3QgZWxlbWVudCBvZiBhcHBfb2JqZWN0cykge1xuICAgICAgICAvLyBTdHJpbmdpZnkgYW5kIHJlcGxhY2UgaW5kZXgtcGF0dGVybiBmb3IgdmlzdWFsaXphdGlvbnNcbiAgICAgICAgYXV4X3NvdXJjZSA9IEpTT04uc3RyaW5naWZ5KGVsZW1lbnQuX3NvdXJjZSk7XG4gICAgICAgIGF1eF9zb3VyY2UgPSBhdXhfc291cmNlLnJlcGxhY2UoL3dhenVoLWFsZXJ0cy9nLCBpZCk7XG4gICAgICAgIGF1eF9zb3VyY2UgPSBKU09OLnBhcnNlKGF1eF9zb3VyY2UpO1xuXG4gICAgICAgIC8vIEJ1bGsgc291cmNlXG4gICAgICAgIGJ1bGtfY29udGVudCA9IHt9O1xuICAgICAgICBidWxrX2NvbnRlbnRbZWxlbWVudC5fdHlwZV0gPSBhdXhfc291cmNlO1xuXG4gICAgICAgIGNvbnN0IHZpc1N0YXRlID0gSlNPTi5wYXJzZShidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbi52aXNTdGF0ZSk7XG4gICAgICAgIGNvbnN0IHRpdGxlID0gdmlzU3RhdGUudGl0bGU7XG5cbiAgICAgICAgaWYgKHZpc1N0YXRlLnR5cGUgJiYgdmlzU3RhdGUudHlwZSA9PT0gJ3RpbWVsaW9uJykge1xuICAgICAgICAgIGxldCBxdWVyeSA9ICcnO1xuICAgICAgICAgIGlmICh0aXRsZSA9PT0gJ1dhenVoIEFwcCBDbHVzdGVyIE92ZXJ2aWV3Jykge1xuICAgICAgICAgICAgZm9yIChjb25zdCBub2RlIG9mIG5vZGVzKSB7XG4gICAgICAgICAgICAgIHF1ZXJ5ICs9IGAuZXMoaW5kZXg9JHtwYXR0ZXJuX25hbWV9LHE9XCJjbHVzdGVyLm5hbWU6ICR7bmFtZX0gQU5EIGNsdXN0ZXIubm9kZTogJHtub2RlLm5hbWV9XCIpLmxhYmVsKFwiJHtub2RlLm5hbWV9XCIpLGA7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBxdWVyeSA9IHF1ZXJ5LnN1YnN0cmluZygwLCBxdWVyeS5sZW5ndGggLSAxKTtcbiAgICAgICAgICB9IGVsc2UgaWYgKHRpdGxlID09PSAnV2F6dWggQXBwIENsdXN0ZXIgT3ZlcnZpZXcgTWFuYWdlcicpIHtcbiAgICAgICAgICAgIHF1ZXJ5ICs9IGAuZXMoaW5kZXg9JHtwYXR0ZXJuX25hbWV9LHE9XCJjbHVzdGVyLm5hbWU6ICR7bmFtZX1cIikubGFiZWwoXCIke25hbWV9IGNsdXN0ZXJcIilgO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpZiAodGl0bGUuc3RhcnRzV2l0aCgnV2F6dWggQXBwIFN0YXRpc3RpY3MnKSkge1xuICAgICAgICAgICAgICBjb25zdCB7IHNlYXJjaFNvdXJjZUpTT04gfSA9IGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLmtpYmFuYVNhdmVkT2JqZWN0TWV0YTtcbiAgICAgICAgICAgICAgYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24ua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT04gPSBzZWFyY2hTb3VyY2VKU09OLnJlcGxhY2UoJ3dhenVoLXN0YXRpc3RpY3MtKicsIHBhdHRlcm5fbmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodGl0bGUuc3RhcnRzV2l0aCgnV2F6dWggQXBwIFN0YXRpc3RpY3MnKSAmJiBuYW1lICE9PSAnLScgJiYgbmFtZSAhPT0gJ2FsbCcgJiYgdmlzU3RhdGUucGFyYW1zLmV4cHJlc3Npb24uaW5jbHVkZXMoJ3E9JykpIHtcbiAgICAgICAgICAgICAgY29uc3QgZXhwcmVzc2lvblJlZ2V4ID0gL3E9J1xcKicvZ2k7XG4gICAgICAgICAgICAgIGNvbnN0IF92aXNTdGF0ZSA9IGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLnZpc1N0YXRlQnlOb2RlXG4gICAgICAgICAgICAgICAgPyBKU09OLnBhcnNlKGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLnZpc1N0YXRlQnlOb2RlKVxuICAgICAgICAgICAgICAgIDogdmlzU3RhdGU7XG4gICAgICAgICAgICAgIHF1ZXJ5ICs9IF92aXNTdGF0ZS5wYXJhbXMuZXhwcmVzc2lvbi5yZXBsYWNlKC93YXp1aC1zdGF0aXN0aWNzLVxcKi9nLCBwYXR0ZXJuX25hbWUpLnJlcGxhY2UoZXhwcmVzc2lvblJlZ2V4LCBgcT1cIm5vZGVOYW1lLmtleXdvcmQ6JHtuYW1lfSBBTkQgYXBpTmFtZS5rZXl3b3JkOiR7bWFzdGVyX25vZGV9XCJgKVxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKFwiTk9ERV9OQU1FXCIsIG5hbWUpXG4gICAgICAgICAgICB9IGVsc2UgaWYgKHRpdGxlLnN0YXJ0c1dpdGgoJ1dhenVoIEFwcCBTdGF0aXN0aWNzJykpIHtcbiAgICAgICAgICAgICAgY29uc3QgZXhwcmVzc2lvblJlZ2V4ID0gL3E9J1xcKicvZ2lcbiAgICAgICAgICAgICAgcXVlcnkgKz0gdmlzU3RhdGUucGFyYW1zLmV4cHJlc3Npb24ucmVwbGFjZSgvd2F6dWgtc3RhdGlzdGljcy1cXCovZywgcGF0dGVybl9uYW1lKS5yZXBsYWNlKGV4cHJlc3Npb25SZWdleCwgYHE9XCJhcGlOYW1lLmtleXdvcmQ6JHttYXN0ZXJfbm9kZX1cImApXG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBxdWVyeSA9IHZpc1N0YXRlLnBhcmFtcy5leHByZXNzaW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHZpc1N0YXRlLnBhcmFtcy5leHByZXNzaW9uID0gcXVlcnkucmVwbGFjZSgvJy9nLCBcIlxcXCJcIik7XG4gICAgICAgICAgYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24udmlzU3RhdGUgPSBKU09OLnN0cmluZ2lmeSh2aXNTdGF0ZSk7XG4gICAgICAgIH1cblxuICAgICAgICB2aXNBcnJheS5wdXNoKHtcbiAgICAgICAgICBhdHRyaWJ1dGVzOiBidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbixcbiAgICAgICAgICB0eXBlOiBlbGVtZW50Ll90eXBlLFxuICAgICAgICAgIGlkOiBlbGVtZW50Ll9pZCxcbiAgICAgICAgICBfdmVyc2lvbjogYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24udmVyc2lvblxuICAgICAgICB9KTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHZpc0FycmF5O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmJ1aWxkQ2x1c3RlclZpc3VhbGl6YXRpb25zUmF3JyxcbiAgICAgICAgZXJyb3IubWVzc2FnZSB8fCBlcnJvclxuICAgICAgKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgY3JlYXRlcyBhIHZpc3VhbGl6YXRpb24gb2YgZGF0YSBpbiByZXFcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IHZpcyBvYmogb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgY3JlYXRlVmlzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdDx7IHBhdHRlcm46IHN0cmluZywgdGFiOiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKFxuICAgICAgICAoIXJlcXVlc3QucGFyYW1zLnRhYi5pbmNsdWRlcygnb3ZlcnZpZXctJykgJiZcbiAgICAgICAgICAhcmVxdWVzdC5wYXJhbXMudGFiLmluY2x1ZGVzKCdhZ2VudHMtJykpXG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdNaXNzaW5nIHBhcmFtZXRlcnMgY3JlYXRpbmcgdmlzdWFsaXphdGlvbnMnKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgdGFiUHJlZml4ID0gcmVxdWVzdC5wYXJhbXMudGFiLmluY2x1ZGVzKCdvdmVydmlldycpXG4gICAgICAgID8gJ292ZXJ2aWV3J1xuICAgICAgICA6ICdhZ2VudHMnO1xuXG4gICAgICBjb25zdCB0YWJTcGxpdCA9IHJlcXVlc3QucGFyYW1zLnRhYi5zcGxpdCgnLScpO1xuICAgICAgY29uc3QgdGFiU3VmaXggPSB0YWJTcGxpdFsxXTtcblxuICAgICAgY29uc3QgZmlsZSA9XG4gICAgICAgIHRhYlByZWZpeCA9PT0gJ292ZXJ2aWV3J1xuICAgICAgICAgID8gT3ZlcnZpZXdWaXN1YWxpemF0aW9uc1t0YWJTdWZpeF1cbiAgICAgICAgICA6IEFnZW50c1Zpc3VhbGl6YXRpb25zW3RhYlN1Zml4XTtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpjcmVhdGVWaXMnLCBgJHt0YWJQcmVmaXh9WyR7dGFiU3VmaXh9XSB3aXRoIGluZGV4IHBhdHRlcm4gJHtyZXF1ZXN0LnBhcmFtcy5wYXR0ZXJufWAsICdkZWJ1ZycpO1xuICAgICAgY29uc3QgbmFtZXNwYWNlID0gY29udGV4dC53YXp1aC5wbHVnaW5zLnNwYWNlcyAmJiBjb250ZXh0LndhenVoLnBsdWdpbnMuc3BhY2VzLnNwYWNlc1NlcnZpY2UgJiYgY29udGV4dC53YXp1aC5wbHVnaW5zLnNwYWNlcy5zcGFjZXNTZXJ2aWNlLmdldFNwYWNlSWQocmVxdWVzdCk7XG4gICAgICBjb25zdCByYXcgPSBhd2FpdCB0aGlzLmJ1aWxkVmlzdWFsaXphdGlvbnNSYXcoXG4gICAgICAgIGZpbGUsXG4gICAgICAgIHJlcXVlc3QucGFyYW1zLnBhdHRlcm4sXG4gICAgICAgIG5hbWVzcGFjZVxuICAgICAgKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgYWNrbm93bGVkZ2U6IHRydWUsIHJhdzogcmF3IH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Y3JlYXRlVmlzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA0MDA3LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBjcmVhdGVzIGEgdmlzdWFsaXphdGlvbiBvZiBjbHVzdGVyXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSB2aXMgb2JqIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNyZWF0ZUNsdXN0ZXJWaXMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0PHsgcGF0dGVybjogc3RyaW5nLCB0YWI6IHN0cmluZyB9LCB1bmtub3duLCBhbnk+LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGlmIChcbiAgICAgICAgIXJlcXVlc3QucGFyYW1zLnBhdHRlcm4gfHxcbiAgICAgICAgIXJlcXVlc3QucGFyYW1zLnRhYiB8fFxuICAgICAgICAhcmVxdWVzdC5ib2R5IHx8XG4gICAgICAgICFyZXF1ZXN0LmJvZHkubm9kZXMgfHxcbiAgICAgICAgIXJlcXVlc3QuYm9keS5ub2Rlcy5hZmZlY3RlZF9pdGVtcyB8fFxuICAgICAgICAhcmVxdWVzdC5ib2R5Lm5vZGVzLm5hbWUgfHxcbiAgICAgICAgKHJlcXVlc3QucGFyYW1zLnRhYiAmJiAhcmVxdWVzdC5wYXJhbXMudGFiLmluY2x1ZGVzKCdjbHVzdGVyLScpKVxuICAgICAgKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignTWlzc2luZyBwYXJhbWV0ZXJzIGNyZWF0aW5nIHZpc3VhbGl6YXRpb25zJyk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHR5cGUgPSByZXF1ZXN0LnBhcmFtcy50YWIuc3BsaXQoJy0nKVsxXTtcblxuICAgICAgY29uc3QgZmlsZSA9IENsdXN0ZXJWaXN1YWxpemF0aW9uc1t0eXBlXTtcbiAgICAgIGNvbnN0IG5vZGVzID0gcmVxdWVzdC5ib2R5Lm5vZGVzLmFmZmVjdGVkX2l0ZW1zO1xuICAgICAgY29uc3QgbmFtZSA9IHJlcXVlc3QuYm9keS5ub2Rlcy5uYW1lO1xuICAgICAgY29uc3QgbWFzdGVyTm9kZSA9IHJlcXVlc3QuYm9keS5ub2Rlcy5tYXN0ZXJfbm9kZTtcblxuICAgICAgY29uc3QgeyBpZDogcGF0dGVybklELCB0aXRsZTogcGF0dGVybk5hbWUgfSA9IHJlcXVlc3QuYm9keS5wYXR0ZXJuO1xuXG4gICAgICBjb25zdCByYXcgPSBhd2FpdCB0aGlzLmJ1aWxkQ2x1c3RlclZpc3VhbGl6YXRpb25zUmF3KFxuICAgICAgICBmaWxlLFxuICAgICAgICBwYXR0ZXJuSUQsXG4gICAgICAgIG5vZGVzLFxuICAgICAgICBuYW1lLFxuICAgICAgICBtYXN0ZXJOb2RlLFxuICAgICAgICBwYXR0ZXJuTmFtZVxuICAgICAgKTtcblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogeyBhY2tub3dsZWRnZTogdHJ1ZSwgcmF3OiByYXcgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpjcmVhdGVDbHVzdGVyVmlzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA0MDA5LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBjaGVja3MgaWYgdGhlcmUgaXMgc2FtcGxlIGFsZXJ0c1xuICAgKiBHRVQgL2VsYXN0aWMvc2FtcGxlYWxlcnRzXG4gICAqIEBwYXJhbSB7Kn0gY29udGV4dFxuICAgKiBAcGFyYW0geyp9IHJlcXVlc3RcbiAgICogQHBhcmFtIHsqfSByZXNwb25zZVxuICAgKiB7YWxlcnRzOiBbLi4uXX0gb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgaGF2ZVNhbXBsZUFsZXJ0cyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgLy8gQ2hlY2sgaWYgd2F6dWggc2FtcGxlIGFsZXJ0cyBpbmRleCBleGlzdHNcbiAgICAgIGNvbnN0IHJlc3VsdHMgPSBhd2FpdCBQcm9taXNlLmFsbChPYmplY3Qua2V5cyhXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JJRVNfVFlQRV9BTEVSVFMpXG4gICAgICAgIC5tYXAoKGNhdGVnb3J5KSA9PiBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgICAgaW5kZXg6IHRoaXMuYnVpbGRTYW1wbGVJbmRleEJ5Q2F0ZWdvcnkoY2F0ZWdvcnkpXG4gICAgICAgIH0pKSk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IHNhbXBsZUFsZXJ0c0luc3RhbGxlZDogcmVzdWx0cy5zb21lKHJlc3VsdCA9PiByZXN1bHQuYm9keSkgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdTYW1wbGUgQWxlcnRzIGNhdGVnb3J5IG5vdCB2YWxpZCcsIDEwMDAsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuICAvKipcbiAgICogVGhpcyBjcmVhdGVzIHNhbXBsZSBhbGVydHMgaW4gd2F6dWgtc2FtcGxlLWFsZXJ0c1xuICAgKiBHRVQgL2VsYXN0aWMvc2FtcGxlYWxlcnRzL3tjYXRlZ29yeX1cbiAgICogQHBhcmFtIHsqfSBjb250ZXh0XG4gICAqIEBwYXJhbSB7Kn0gcmVxdWVzdFxuICAgKiBAcGFyYW0geyp9IHJlc3BvbnNlXG4gICAqIHthbGVydHM6IFsuLi5dfSBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBoYXZlU2FtcGxlQWxlcnRzT2ZDYXRlZ29yeShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3Q8eyBjYXRlZ29yeTogc3RyaW5nIH0+LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHNhbXBsZUFsZXJ0c0luZGV4ID0gdGhpcy5idWlsZFNhbXBsZUluZGV4QnlDYXRlZ29yeShyZXF1ZXN0LnBhcmFtcy5jYXRlZ29yeSk7XG4gICAgICAvLyBDaGVjayBpZiB3YXp1aCBzYW1wbGUgYWxlcnRzIGluZGV4IGV4aXN0c1xuICAgICAgY29uc3QgZXhpc3RzU2FtcGxlSW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleFxuICAgICAgfSk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IGluZGV4OiBzYW1wbGVBbGVydHNJbmRleCwgZXhpc3RzOiBleGlzdHNTYW1wbGVJbmRleC5ib2R5IH1cbiAgICAgIH0pXG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3dhenVoLWVsYXN0aWM6aGF2ZVNhbXBsZUFsZXJ0c09mQ2F0ZWdvcnknLFxuICAgICAgICBgRXJyb3IgY2hlY2tpbmcgaWYgdGhlcmUgYXJlIHNhbXBsZSBhbGVydHMgaW5kaWNlczogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWBcbiAgICAgICk7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShgRXJyb3IgY2hlY2tpbmcgaWYgdGhlcmUgYXJlIHNhbXBsZSBhbGVydHMgaW5kaWNlczogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWAsIDEwMDAsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuICAvKipcbiAgICogVGhpcyBjcmVhdGVzIHNhbXBsZSBhbGVydHMgaW4gd2F6dWgtc2FtcGxlLWFsZXJ0c1xuICAgKiBQT1NUIC9lbGFzdGljL3NhbXBsZWFsZXJ0cy97Y2F0ZWdvcnl9XG4gICAqIHtcbiAgICogICBcIm1hbmFnZXJcIjoge1xuICAgKiAgICAgIFwibmFtZVwiOiBcIm1hbmFnZXJfbmFtZVwiXG4gICAqICAgIH0sXG4gICAqICAgIGNsdXN0ZXI6IHtcbiAgICogICAgICBuYW1lOiBcIm15Y2x1c3RlclwiLFxuICAgKiAgICAgIG5vZGU6IFwibXlub2RlXCJcbiAgICogICAgfVxuICAgKiB9XG4gICAqIEBwYXJhbSB7Kn0gY29udGV4dFxuICAgKiBAcGFyYW0geyp9IHJlcXVlc3RcbiAgICogQHBhcmFtIHsqfSByZXNwb25zZVxuICAgKiB7aW5kZXg6IHN0cmluZywgYWxlcnRzOiBbLi4uXSwgY291bnQ6IG51bWJlcn0gb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgY3JlYXRlU2FtcGxlQWxlcnRzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdDx7IGNhdGVnb3J5OiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICBjb25zdCBzYW1wbGVBbGVydHNJbmRleCA9IHRoaXMuYnVpbGRTYW1wbGVJbmRleEJ5Q2F0ZWdvcnkocmVxdWVzdC5wYXJhbXMuY2F0ZWdvcnkpO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIENoZWNrIGlmIHVzZXIgaGFzIGFkbWluaXN0cmF0b3Igcm9sZSBpbiB0b2tlblxuICAgICAgY29uc3QgdG9rZW4gPSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCAnd3otdG9rZW4nKTtcbiAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIHRva2VuIHByb3ZpZGVkJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICBjb25zdCBkZWNvZGVkVG9rZW4gPSBqd3REZWNvZGUodG9rZW4pO1xuICAgICAgaWYgKCFkZWNvZGVkVG9rZW4pIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIHBlcm1pc3Npb25zIGluIHRva2VuJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICBpZiAoIWRlY29kZWRUb2tlbi5yYmFjX3JvbGVzIHx8ICFkZWNvZGVkVG9rZW4ucmJhY19yb2xlcy5pbmNsdWRlcyhXQVpVSF9ST0xFX0FETUlOSVNUUkFUT1JfSUQpKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBhZG1pbmlzdHJhdG9yIHJvbGUnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIC8vIENoZWNrIHRoZSBwcm92aWRlZCB0b2tlbiBpcyB2YWxpZFxuICAgICAgY29uc3QgYXBpSG9zdElEID0gZ2V0Q29va2llVmFsdWVCeU5hbWUocmVxdWVzdC5oZWFkZXJzLmNvb2tpZSwgJ3d6LWFwaScpO1xuICAgICAgaWYgKCFhcGlIb3N0SUQpIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIEFQSSBpZCBwcm92aWRlZCcsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgY29uc3QgcmVzcG9uc2VUb2tlbklzV29ya2luZyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoJ0dFVCcsIGAvL2AsIHt9LCB7IGFwaUhvc3RJRCB9KTtcbiAgICAgIGlmIChyZXNwb25zZVRva2VuSXNXb3JraW5nLnN0YXR1cyAhPT0gMjAwKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdUb2tlbiBpcyBub3QgdmFsaWQnLCA1MDAsIDUwMCwgcmVzcG9uc2UpO1xuICAgICAgfTtcblxuICAgICAgY29uc3QgYnVsa1ByZWZpeCA9IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgaW5kZXg6IHtcbiAgICAgICAgICBfaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgICAgY29uc3QgYWxlcnRHZW5lcmF0ZVBhcmFtcyA9IHJlcXVlc3QuYm9keSAmJiByZXF1ZXN0LmJvZHkucGFyYW1zIHx8IHt9O1xuXG4gICAgICBjb25zdCBzYW1wbGVBbGVydHMgPSBXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JJRVNfVFlQRV9BTEVSVFNbcmVxdWVzdC5wYXJhbXMuY2F0ZWdvcnldLm1hcCgodHlwZUFsZXJ0KSA9PiBnZW5lcmF0ZUFsZXJ0cyh7IC4uLnR5cGVBbGVydCwgLi4uYWxlcnRHZW5lcmF0ZVBhcmFtcyB9LCByZXF1ZXN0LmJvZHkuYWxlcnRzIHx8IHR5cGVBbGVydC5hbGVydHMgfHwgV0FaVUhfU0FNUExFX0FMRVJUU19ERUZBVUxUX05VTUJFUl9BTEVSVFMpKS5mbGF0KCk7XG4gICAgICBjb25zdCBidWxrID0gc2FtcGxlQWxlcnRzLm1hcChzYW1wbGVBbGVydCA9PiBgJHtidWxrUHJlZml4fVxcbiR7SlNPTi5zdHJpbmdpZnkoc2FtcGxlQWxlcnQpfVxcbmApLmpvaW4oJycpO1xuXG4gICAgICAvLyBJbmRleCBhbGVydHNcblxuICAgICAgLy8gQ2hlY2sgaWYgd2F6dWggc2FtcGxlIGFsZXJ0cyBpbmRleCBleGlzdHNcbiAgICAgIGNvbnN0IGV4aXN0c1NhbXBsZUluZGV4ID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZXhpc3RzKHtcbiAgICAgICAgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4XG4gICAgICB9KTtcbiAgICAgIGlmICghZXhpc3RzU2FtcGxlSW5kZXguYm9keSkge1xuICAgICAgICAvLyBDcmVhdGUgd2F6dWggc2FtcGxlIGFsZXJ0cyBpbmRleFxuXG4gICAgICAgIGNvbnN0IGNvbmZpZ3VyYXRpb24gPSB7XG4gICAgICAgICAgc2V0dGluZ3M6IHtcbiAgICAgICAgICAgIGluZGV4OiB7XG4gICAgICAgICAgICAgIG51bWJlcl9vZl9zaGFyZHM6IFdBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfU0hBUkRTLFxuICAgICAgICAgICAgICBudW1iZXJfb2ZfcmVwbGljYXM6IFdBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfUkVQTElDQVNcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH07XG5cbiAgICAgICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuY3JlYXRlKHtcbiAgICAgICAgICBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXgsXG4gICAgICAgICAgYm9keTogY29uZmlndXJhdGlvblxuICAgICAgICB9KTtcbiAgICAgICAgbG9nKFxuICAgICAgICAgICd3YXp1aC1lbGFzdGljOmNyZWF0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgICAgYENyZWF0ZWQgJHtzYW1wbGVBbGVydHNJbmRleH0gaW5kZXhgLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmJ1bGsoe1xuICAgICAgICBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXgsXG4gICAgICAgIGJvZHk6IGJ1bGtcbiAgICAgIH0pO1xuICAgICAgbG9nKFxuICAgICAgICAnd2F6dWgtZWxhc3RpYzpjcmVhdGVTYW1wbGVBbGVydHMnLFxuICAgICAgICBgQWRkZWQgc2FtcGxlIGFsZXJ0cyB0byAke3NhbXBsZUFsZXJ0c0luZGV4fSBpbmRleGAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IGluZGV4OiBzYW1wbGVBbGVydHNJbmRleCwgYWxlcnRDb3VudDogc2FtcGxlQWxlcnRzLmxlbmd0aCB9XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKFxuICAgICAgICAnd2F6dWgtZWxhc3RpYzpjcmVhdGVTYW1wbGVBbGVydHMnLFxuICAgICAgICBgRXJyb3IgYWRkaW5nIHNhbXBsZSBhbGVydHMgdG8gJHtzYW1wbGVBbGVydHNJbmRleH0gaW5kZXg6ICR7ZXJyb3IubWVzc2FnZSB8fCBlcnJvcn1gXG4gICAgICApO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgMTAwMCwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG4gIC8qKlxuICAgKiBUaGlzIGRlbGV0ZXMgc2FtcGxlIGFsZXJ0c1xuICAgKiBAcGFyYW0geyp9IGNvbnRleHRcbiAgICogQHBhcmFtIHsqfSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7Kn0gcmVzcG9uc2VcbiAgICoge3Jlc3VsdDogXCJkZWxldGVkXCIsIGluZGV4OiBzdHJpbmd9IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGRlbGV0ZVNhbXBsZUFsZXJ0cyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3Q8eyBjYXRlZ29yeTogc3RyaW5nIH0+LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgLy8gRGVsZXRlIFdhenVoIHNhbXBsZSBhbGVydCBpbmRleFxuXG4gICAgY29uc3Qgc2FtcGxlQWxlcnRzSW5kZXggPSB0aGlzLmJ1aWxkU2FtcGxlSW5kZXhCeUNhdGVnb3J5KHJlcXVlc3QucGFyYW1zLmNhdGVnb3J5KTtcblxuICAgIHRyeSB7XG4gICAgICAvLyBDaGVjayBpZiB1c2VyIGhhcyBhZG1pbmlzdHJhdG9yIHJvbGUgaW4gdG9rZW5cbiAgICAgIGNvbnN0IHRva2VuID0gZ2V0Q29va2llVmFsdWVCeU5hbWUocmVxdWVzdC5oZWFkZXJzLmNvb2tpZSwgJ3d6LXRva2VuJyk7XG4gICAgICBpZiAoIXRva2VuKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyB0b2tlbiBwcm92aWRlZCcsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgY29uc3QgZGVjb2RlZFRva2VuID0gand0RGVjb2RlKHRva2VuKTtcbiAgICAgIGlmICghZGVjb2RlZFRva2VuKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBwZXJtaXNzaW9ucyBpbiB0b2tlbicsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgaWYgKCFkZWNvZGVkVG9rZW4ucmJhY19yb2xlcyB8fCAhZGVjb2RlZFRva2VuLnJiYWNfcm9sZXMuaW5jbHVkZXMoV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX0lEKSkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gYWRtaW5pc3RyYXRvciByb2xlJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICAvLyBDaGVjayB0aGUgcHJvdmlkZWQgdG9rZW4gaXMgdmFsaWRcbiAgICAgIGNvbnN0IGFwaUhvc3RJRCA9IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei1hcGknKTtcbiAgICAgIGlmICghYXBpSG9zdElEKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBBUEkgaWQgcHJvdmlkZWQnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIGNvbnN0IHJlc3BvbnNlVG9rZW5Jc1dvcmtpbmcgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KCdHRVQnLCBgLy9gLCB7fSwgeyBhcGlIb3N0SUQgfSk7XG4gICAgICBpZiAocmVzcG9uc2VUb2tlbklzV29ya2luZy5zdGF0dXMgIT09IDIwMCkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnVG9rZW4gaXMgbm90IHZhbGlkJywgNTAwLCA1MDAsIHJlc3BvbnNlKTtcbiAgICAgIH07XG5cbiAgICAgIC8vIENoZWNrIGlmIFdhenVoIHNhbXBsZSBhbGVydHMgaW5kZXggZXhpc3RzXG4gICAgICBjb25zdCBleGlzdHNTYW1wbGVJbmRleCA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLmluZGljZXMuZXhpc3RzKHtcbiAgICAgICAgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4XG4gICAgICB9KTtcbiAgICAgIGlmIChleGlzdHNTYW1wbGVJbmRleC5ib2R5KSB7XG4gICAgICAgIC8vIERlbGV0ZSBXYXp1aCBzYW1wbGUgYWxlcnRzIGluZGV4XG4gICAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLmluZGljZXMuZGVsZXRlKHsgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4IH0pO1xuICAgICAgICBsb2coXG4gICAgICAgICAgJ3dhenVoLWVsYXN0aWM6ZGVsZXRlU2FtcGxlQWxlcnRzJyxcbiAgICAgICAgICBgRGVsZXRlZCAke3NhbXBsZUFsZXJ0c0luZGV4fSBpbmRleGAsXG4gICAgICAgICAgJ2RlYnVnJ1xuICAgICAgICApO1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHsgcmVzdWx0OiAnZGVsZXRlZCcsIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleCB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoYCR7c2FtcGxlQWxlcnRzSW5kZXh9IGluZGV4IGRvZXNuJ3QgZXhpc3RgLCAxMDAwLCA1MDAsIHJlc3BvbnNlKVxuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmRlbGV0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgIGBFcnJvciBkZWxldGluZyBzYW1wbGUgYWxlcnRzIG9mICR7c2FtcGxlQWxlcnRzSW5kZXh9IGluZGV4OiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICAgKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDEwMDAsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGFsZXJ0cyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaChyZXF1ZXN0LmJvZHkpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogZGF0YS5ib2R5XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmFsZXJ0cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNDAxMCwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLy8gQ2hlY2sgaWYgdGhlcmUgYXJlIGluZGljZXMgZm9yIFN0YXRpc3RpY3NcbiAgYXN5bmMgZXhpc3RTdGF0aXN0aWNzSW5kaWNlcyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29uZmlnID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgICAgY29uc3Qgc3RhdGlzdGljc1BhdHRlcm4gPSBgJHtjb25maWdbJ2Nyb24ucHJlZml4J10gfHwgJ3dhenVoJ30tJHtjb25maWdbJ2Nyb24uc3RhdGlzdGljcy5pbmRleC5uYW1lJ10gfHwgJ3N0YXRpc3RpY3MnfSpgOyAvL1RPRE86IHJlcGxhY2UgYnkgZGVmYXVsdCBhcyBjb25zdGFudHMgaW5zdGVhZCBoYXJkY29kZWQgKCd3YXp1aCcgYW5kICdzdGF0aXN0aWNzJylcbiAgICAgIGNvbnN0IGV4aXN0SW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBzdGF0aXN0aWNzUGF0dGVybixcbiAgICAgICAgYWxsb3dfbm9faW5kaWNlczogZmFsc2VcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogZXhpc3RJbmRleC5ib2R5XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmV4aXN0c1N0YXRpc3RpY3NJbmRpY2VzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAxMDAwLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyB1c2luZ0NyZWRlbnRpYWxzKGNvbnRleHQpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5jbHVzdGVyLmdldFNldHRpbmdzKFxuICAgICAgICB7IGluY2x1ZGVfZGVmYXVsdHM6IHRydWUgfVxuICAgICAgKTtcbiAgICAgIHJldHVybiAoKCgoKGRhdGEgfHwge30pLmJvZHkgfHwge30pLmRlZmF1bHRzIHx8IHt9KS54cGFjayB8fCB7fSkuc2VjdXJpdHkgfHwge30pLnVzZXIgIT09IG51bGw7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9O1xufVxuIl19