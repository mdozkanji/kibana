"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhApiCtrl = void 0;

var _errorResponse = require("../lib/error-response");

var _json2csv = require("json2csv");

var _logger = require("../lib/logger");

var _csvKeyEquivalence = require("../../common/csv-key-equivalence");

var _apiErrorsEquivalence = require("../lib/api-errors-equivalence");

var _endpoints = _interopRequireDefault(require("../../common/api-info/endpoints"));

var _queue = require("../start/queue");

var _fs = _interopRequireDefault(require("fs"));

var _manageHosts = require("../lib/manage-hosts");

var _updateRegistry = require("../lib/update-registry");

var _jwtDecode = _interopRequireDefault(require("jwt-decode"));

var _cacheApiUserHasRunAs = require("../lib/cache-api-user-has-run-as");

var _cookie = require("../lib/cookie");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class WazuhApiCtrl {
  constructor() {
    _defineProperty(this, "manageHosts", void 0);

    _defineProperty(this, "updateRegistry", void 0);

    // this.monitoringInstance = new Monitoring(server, true);
    this.manageHosts = new _manageHosts.ManageHosts();
    this.updateRegistry = new _updateRegistry.UpdateRegistry();
  }

  async getToken(context, request, response) {
    try {
      const {
        force,
        idHost
      } = request.body;
      const {
        username
      } = await context.wazuh.security.getCurrentUser(request, context);

      if (!force && request.headers.cookie && username === (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-user') && idHost === (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api')) {
        const wzToken = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

        if (wzToken) {
          try {
            // if the current token is not a valid jwt token we ask for a new one
            const decodedToken = (0, _jwtDecode.default)(wzToken);
            const expirationTime = decodedToken.exp - Date.now() / 1000;

            if (wzToken && expirationTime > 0) {
              return response.ok({
                body: {
                  token: wzToken
                }
              });
            }
          } catch (error) {
            (0, _logger.log)('wazuh-api:getToken', error.message || error);
          }
        }
      }

      let token;

      if ((await _cacheApiUserHasRunAs.APIUserAllowRunAs.canUse(idHost)) == _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ENABLED) {
        token = await context.wazuh.api.client.asCurrentUser.authenticate(idHost);
      } else {
        token = await context.wazuh.api.client.asInternalUser.authenticate(idHost);
      }

      ;
      let textSecure = '';

      if (context.wazuh.server.info.protocol === 'https') {
        textSecure = ';Secure';
      }

      return response.ok({
        headers: {
          'set-cookie': [`wz-token=${token};Path=/;HttpOnly${textSecure}`, `wz-user=${username};Path=/;HttpOnly${textSecure}`, `wz-api=${idHost};Path=/;HttpOnly`]
        },
        body: {
          token
        }
      });
    } catch (error) {
      const errorMessage = ((error.response || {}).data || {}).detail || error.message || error;
      (0, _logger.log)('wazuh-api:getToken', errorMessage);
      return (0, _errorResponse.ErrorResponse)(`Error getting the authorization token: ${errorMessage}`, 3000, 500, response);
    }
  }
  /**
   * Returns if the wazuh-api configuration is working
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async checkStoredAPI(context, request, response) {
    try {
      // Get config from wazuh.yml
      const id = request.body.id;
      const api = await this.manageHosts.getHostById(id); // Check Manage Hosts

      if (!Object.keys(api).length) {
        throw new Error('Could not find Wazuh API entry on wazuh.yml');
      }

      (0, _logger.log)('wazuh-api:checkStoredAPI', `${id} exists`, 'debug'); // Fetch needed information about the cluster and the manager itself

      const responseManagerInfo = await context.wazuh.api.client.asInternalUser.request('get', `/manager/info`, {}, {
        apiHostID: id,
        forceRefresh: true
      }); // Look for socket-related errors

      if (this.checkResponseIsDown(responseManagerInfo)) {
        return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${responseManagerInfo.data.detail || 'Wazuh not ready yet'}`, 3099, 500, response);
      } // If we have a valid response from the Wazuh API


      if (responseManagerInfo.status === 200 && responseManagerInfo.data) {
        // Clear and update cluster information before being sent back to frontend
        delete api.cluster_info;
        const responseAgents = await context.wazuh.api.client.asInternalUser.request('GET', `/agents`, {
          params: {
            agents_list: '000'
          }
        }, {
          apiHostID: id
        });

        if (responseAgents.status === 200) {
          const managerName = responseAgents.data.data.affected_items[0].manager;
          const responseClusterStatus = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/status`, {}, {
            apiHostID: id
          });

          if (responseClusterStatus.status === 200) {
            if (responseClusterStatus.data.data.enabled === 'yes') {
              const responseClusterLocalInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/local/info`, {}, {
                apiHostID: id
              });

              if (responseClusterLocalInfo.status === 200) {
                const clusterEnabled = responseClusterStatus.data.data.enabled === 'yes';
                api.cluster_info = {
                  status: clusterEnabled ? 'enabled' : 'disabled',
                  manager: managerName,
                  node: responseClusterLocalInfo.data.data.affected_items[0].node,
                  cluster: clusterEnabled ? responseClusterLocalInfo.data.data.affected_items[0].cluster : 'Disabled'
                };
              }
            } else {
              // Cluster mode is not active
              api.cluster_info = {
                status: 'disabled',
                manager: managerName,
                cluster: 'Disabled'
              };
            }
          } else {
            // Cluster mode is not active
            api.cluster_info = {
              status: 'disabled',
              manager: managerName,
              cluster: 'Disabled'
            };
          }

          if (api.cluster_info) {
            // Update cluster information in the wazuh-registry.json
            await this.updateRegistry.updateClusterInfo(id, api.cluster_info); // Hide Wazuh API secret, username, password

            const copied = { ...api
            };
            copied.secret = '****';
            copied.password = '****';
            return response.ok({
              body: {
                statusCode: 200,
                data: copied,
                idChanged: request.body.idChanged || null
              }
            });
          }
        }
      } // If we have an invalid response from the Wazuh API


      throw new Error(responseManagerInfo.data.detail || `${api.url}:${api.port} is unreachable`);
    } catch (error) {
      if (error.code === 'EPROTO') {
        return response.ok({
          body: {
            statusCode: 200,
            data: {
              password: '****',
              apiIsDown: true
            }
          }
        });
      } else if (error.code === 'ECONNREFUSED') {
        return response.ok({
          body: {
            statusCode: 200,
            data: {
              password: '****',
              apiIsDown: true
            }
          }
        });
      } else {
        try {
          const apis = await this.manageHosts.getHosts();

          for (const api of apis) {
            try {
              const id = Object.keys(api)[0];
              const responseManagerInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/manager/info`, {}, {
                apiHostID: id
              });

              if (this.checkResponseIsDown(responseManagerInfo)) {
                return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${response.data.detail || 'Wazuh not ready yet'}`, 3099, 500, response);
              }

              if (responseManagerInfo.status === 200) {
                request.body.id = id;
                request.body.idChanged = id;
                return await this.checkStoredAPI(context, request, response);
              }
            } catch (error) {} // eslint-disable-line

          }
        } catch (error) {
          (0, _logger.log)('wazuh-api:checkStoredAPI', error.message || error);
          return (0, _errorResponse.ErrorResponse)(error.message || error, 3020, 500, response);
        }

        (0, _logger.log)('wazuh-api:checkStoredAPI', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 3002, 500, response);
      }
    }
  }
  /**
   * This perfoms a validation of API params
   * @param {Object} body API params
   */


  validateCheckApiParams(body) {
    if (!('username' in body)) {
      return 'Missing param: API USERNAME';
    }

    if (!('password' in body) && !('id' in body)) {
      return 'Missing param: API PASSWORD';
    }

    if (!('url' in body)) {
      return 'Missing param: API URL';
    }

    if (!('port' in body)) {
      return 'Missing param: API PORT';
    }

    if (!body.url.includes('https://') && !body.url.includes('http://')) {
      return 'protocol_error';
    }

    return false;
  }
  /**
   * This check the wazuh-api configuration received in the POST body will work
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async checkAPI(context, request, response) {
    try {
      let apiAvailable = null; // const notValid = this.validateCheckApiParams(request.body);
      // if (notValid) return ErrorResponse(notValid, 3003, 500, response);

      (0, _logger.log)('wazuh-api:checkAPI', `${request.body.id} is valid`, 'debug'); // Check if a Wazuh API id is given (already stored API)

      const data = await this.manageHosts.getHostById(request.body.id);

      if (data) {
        apiAvailable = data;
      } else {
        (0, _logger.log)('wazuh-api:checkAPI', `API ${request.body.id} not found`);
        return (0, _errorResponse.ErrorResponse)(`The API ${request.body.id} was not found`, 3029, 500, response);
      }

      const options = {
        apiHostID: request.body.id
      };

      if (request.body.forceRefresh) {
        options["forceRefresh"] = request.body.forceRefresh;
      }

      let responseManagerInfo;

      try {
        responseManagerInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/manager/info`, {}, options);
      } catch (error) {
        var _error$response, _error$response$data;

        return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${((_error$response = error.response) === null || _error$response === void 0 ? void 0 : (_error$response$data = _error$response.data) === null || _error$response$data === void 0 ? void 0 : _error$response$data.detail) || 'Wazuh not ready yet'}`, 3099, 500, response);
      }

      (0, _logger.log)('wazuh-api:checkAPI', `${request.body.id} credentials are valid`, 'debug');

      if (responseManagerInfo.status === 200 && responseManagerInfo.data) {
        let responseAgents = await context.wazuh.api.client.asInternalUser.request('GET', `/agents`, {
          params: {
            agents_list: '000'
          }
        }, {
          apiHostID: request.body.id
        });

        if (responseAgents.status === 200) {
          const managerName = responseAgents.data.data.affected_items[0].manager;
          let responseCluster = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/status`, {}, {
            apiHostID: request.body.id
          }); // Check the run_as for the API user and update it

          let apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ALL_DISABLED;
          const responseApiUserAllowRunAs = await context.wazuh.api.client.asInternalUser.request('GET', `/security/users/me`, {}, {
            apiHostID: request.body.id
          });

          if (responseApiUserAllowRunAs.status === 200) {
            const allow_run_as = responseApiUserAllowRunAs.data.data.affected_items[0].allow_run_as;
            if (allow_run_as && apiAvailable && apiAvailable.run_as) // HOST AND USER ENABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ENABLED;else if (!allow_run_as && apiAvailable && apiAvailable.run_as) // HOST ENABLED AND USER DISABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.USER_NOT_ALLOWED;else if (allow_run_as && (!apiAvailable || !apiAvailable.run_as)) // USER ENABLED AND HOST DISABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.HOST_DISABLED;else if (!allow_run_as && (!apiAvailable || !apiAvailable.run_as)) // HOST AND USER DISABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ALL_DISABLED;
          }

          _cacheApiUserHasRunAs.CacheInMemoryAPIUserAllowRunAs.set(request.body.id, apiAvailable.username, apiUserAllowRunAs);

          if (responseCluster.status === 200) {
            (0, _logger.log)('wazuh-api:checkStoredAPI', `Wazuh API response is valid`, 'debug');

            if (responseCluster.data.data.enabled === 'yes') {
              // If cluster mode is active
              let responseClusterLocal = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/local/info`, {}, {
                apiHostID: request.body.id
              });

              if (responseClusterLocal.status === 200) {
                return response.ok({
                  body: {
                    manager: managerName,
                    node: responseClusterLocal.data.data.affected_items[0].node,
                    cluster: responseClusterLocal.data.data.affected_items[0].cluster,
                    status: 'enabled',
                    allow_run_as: apiUserAllowRunAs
                  }
                });
              }
            } else {
              // Cluster mode is not active
              return response.ok({
                body: {
                  manager: managerName,
                  cluster: 'Disabled',
                  status: 'disabled',
                  allow_run_as: apiUserAllowRunAs
                }
              });
            }
          }
        }
      }
    } catch (error) {
      (0, _logger.log)('wazuh-api:checkAPI', error.message || error);

      if (error && error.response && error.response.status === 401) {
        return (0, _errorResponse.ErrorResponse)(`Unathorized. Please check API credentials. ${error.response.data.message}`, 401, 401, response);
      }

      if (error && error.response && error.response.data && error.response.data.detail) {
        return (0, _errorResponse.ErrorResponse)(error.response.data.detail, error.response.status || 500, error.response.status || 500, response);
      }

      if (error.code === 'EPROTO') {
        return (0, _errorResponse.ErrorResponse)('Wrong protocol being used to connect to the Wazuh API', 3005, 500, response);
      }

      return (0, _errorResponse.ErrorResponse)(error.message || error, 3005, 500, response);
    }
  }

  checkResponseIsDown(response) {
    if (response.status !== 200) {
      // Avoid "Error communicating with socket" like errors
      const socketErrorCodes = [1013, 1014, 1017, 1018, 1019];
      const status = (response.data || {}).status || 1;
      const isDown = socketErrorCodes.includes(status);
      isDown && (0, _logger.log)('wazuh-api:makeRequest', 'Wazuh API is online but Wazuh is not ready yet');
      return isDown;
    }

    return false;
  }
  /**
   * Check main Wazuh daemons status
   * @param {*} context Endpoint context
   * @param {*} api API entry stored in .wazuh
   * @param {*} path Optional. Wazuh API target path.
   */


  async checkDaemons(context, api, path) {
    try {
      const response = await context.wazuh.api.client.asInternalUser.request('GET', '/manager/status', {}, {
        apiHostID: api.id
      });
      const daemons = ((((response || {}).data || {}).data || {}).affected_items || [])[0] || {};
      const isCluster = ((api || {}).cluster_info || {}).status === 'enabled' && typeof daemons['wazuh-clusterd'] !== 'undefined';
      const wazuhdbExists = typeof daemons['wazuh-db'] !== 'undefined';
      const execd = daemons['wazuh-execd'] === 'running';
      const modulesd = daemons['wazuh-modulesd'] === 'running';
      const wazuhdb = wazuhdbExists ? daemons['wazuh-db'] === 'running' : true;
      const clusterd = isCluster ? daemons['wazuh-clusterd'] === 'running' : true;
      const isValid = execd && modulesd && wazuhdb && clusterd;
      isValid && (0, _logger.log)('wazuh-api:checkDaemons', `Wazuh is ready`, 'debug');

      if (path === '/ping') {
        return {
          isValid
        };
      }

      if (!isValid) {
        throw new Error('Wazuh not ready yet');
      }
    } catch (error) {
      (0, _logger.log)('wazuh-api:checkDaemons', error.message || error);
      return Promise.reject(error);
    }
  }

  sleep(timeMs) {
    // eslint-disable-next-line
    return new Promise((resolve, reject) => {
      setTimeout(resolve, timeMs);
    });
  }
  /**
   * Helper method for Dev Tools.
   * https://documentation.wazuh.com/current/user-manual/api/reference.html
   * Depending on the method and the path some parameters should be an array or not.
   * Since we allow the user to write the request using both comma-separated and array as well,
   * we need to check if it should be transformed or not.
   * @param {*} method The request method
   * @param {*} path The Wazuh API path
   */


  shouldKeepArrayAsIt(method, path) {
    // Methods that we must respect a do not transform them
    const isAgentsRestart = method === 'POST' && path === '/agents/restart';
    const isActiveResponse = method === 'PUT' && path.startsWith('/active-response/');
    const isAddingAgentsToGroup = method === 'POST' && path.startsWith('/agents/group/'); // Returns true only if one of the above conditions is true

    return isAgentsRestart || isActiveResponse || isAddingAgentsToGroup;
  }
  /**
   * This performs a request over Wazuh API and returns its response
   * @param {String} method Method: GET, PUT, POST, DELETE
   * @param {String} path API route
   * @param {Object} data data and params to perform the request
   * @param {String} id API id
   * @param {Object} response
   * @returns {Object} API response or ErrorResponse
   */


  async makeRequest(context, method, path, data, id, response) {
    const devTools = !!(data || {}).devTools;

    try {
      const api = await this.manageHosts.getHostById(id);

      if (devTools) {
        delete data.devTools;
      }

      if (!Object.keys(api).length) {
        (0, _logger.log)('wazuh-api:makeRequest', 'Could not get host credentials'); //Can not get credentials from wazuh-hosts

        return (0, _errorResponse.ErrorResponse)('Could not get host credentials', 3011, 404, response);
      }

      if (!data) {
        data = {};
      }

      ;

      if (!data.headers) {
        data.headers = {};
      }

      ;
      const options = {
        apiHostID: id
      }; // Set content type application/xml if needed

      if (typeof (data || {}).body === 'string' && (data || {}).origin === 'xmleditor') {
        data.headers['content-type'] = 'application/xml';
        delete data.origin;
      }

      if (typeof (data || {}).body === 'string' && (data || {}).origin === 'json') {
        data.headers['content-type'] = 'application/json';
        delete data.origin;
      }

      if (typeof (data || {}).body === 'string' && (data || {}).origin === 'raw') {
        data.headers['content-type'] = 'application/octet-stream';
        delete data.origin;
      }

      const delay = (data || {}).delay || 0;

      if (delay) {
        (0, _queue.addJobToQueue)({
          startAt: new Date(Date.now() + delay),
          run: async () => {
            try {
              await context.wazuh.api.client.asCurrentUser.request(method, path, data, options);
            } catch (error) {
              (0, _logger.log)('queue:delayApiRequest', `An error ocurred in the delayed request: "${method} ${path}": ${error.message || error}`);
            }

            ;
          }
        });
        return response.ok({
          body: {
            error: 0,
            message: 'Success'
          }
        });
      }

      if (path === '/ping') {
        try {
          const check = await this.checkDaemons(context, api, path);
          return check;
        } catch (error) {
          const isDown = (error || {}).code === 'ECONNREFUSED';

          if (!isDown) {
            (0, _logger.log)('wazuh-api:makeRequest', 'Wazuh API is online but Wazuh is not ready yet');
            return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${error.message || 'Wazuh not ready yet'}`, 3099, 500, response);
          }
        }
      }

      (0, _logger.log)('wazuh-api:makeRequest', `${method} ${path}`, 'debug'); // Extract keys from parameters

      const dataProperties = Object.keys(data); // Transform arrays into comma-separated string if applicable.
      // The reason is that we are accepting arrays for comma-separated
      // parameters in the Dev Tools

      if (!this.shouldKeepArrayAsIt(method, path)) {
        for (const key of dataProperties) {
          if (Array.isArray(data[key])) {
            data[key] = data[key].join();
          }
        }
      }

      const responseToken = await context.wazuh.api.client.asCurrentUser.request(method, path, data, options);
      const responseIsDown = this.checkResponseIsDown(responseToken);

      if (responseIsDown) {
        return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${response.body.message || 'Wazuh not ready yet'}`, 3099, 500, response);
      }

      let responseBody = (responseToken || {}).data || {};

      if (!responseBody) {
        responseBody = typeof responseBody === 'string' && path.includes('/files') && method === 'GET' ? ' ' : false;
        response.data = responseBody;
      }

      const responseError = response.status !== 200 ? response.status : false;

      if (!responseError && responseBody) {
        //cleanKeys(response);
        return response.ok({
          body: responseToken.data
        });
      }

      if (responseError && devTools) {
        return response.ok({
          body: response.data
        });
      }

      throw responseError && responseBody.detail ? {
        message: responseBody.detail,
        code: responseError
      } : new Error('Unexpected error fetching data from the Wazuh API');
    } catch (error) {
      if (error && error.response && error.response.status === 401) {
        return (0, _errorResponse.ErrorResponse)(error.message || error, error.code ? `Wazuh API error: ${error.code}` : 3013, 401, response);
      }

      const errorMsg = (error.response || {}).data || error.message;
      (0, _logger.log)('wazuh-api:makeRequest', errorMsg || error);

      if (devTools) {
        return response.ok({
          body: {
            error: '3013',
            message: errorMsg || error
          }
        });
      } else {
        if ((error || {}).code && _apiErrorsEquivalence.ApiErrorEquivalence[error.code]) {
          error.message = _apiErrorsEquivalence.ApiErrorEquivalence[error.code];
        }

        return (0, _errorResponse.ErrorResponse)(errorMsg.detail || error, error.code ? `Wazuh API error: ${error.code}` : 3013, 500, response);
      }
    }
  }
  /**
   * This make a request to API
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} api response or ErrorResponse
   */


  requestApi(context, request, response) {
    const idApi = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

    if (idApi !== request.body.id) {
      // if the current token belongs to a different API id, we relogin to obtain a new token
      return (0, _errorResponse.ErrorResponse)('status code 401', 401, 401, response);
    }

    if (!request.body.method) {
      return (0, _errorResponse.ErrorResponse)('Missing param: method', 3015, 400, response);
    } else if (!request.body.method.match(/^(?:GET|PUT|POST|DELETE)$/)) {
      (0, _logger.log)('wazuh-api:makeRequest', 'Request method is not valid.'); //Method is not a valid HTTP request method

      return (0, _errorResponse.ErrorResponse)('Request method is not valid.', 3015, 400, response);
    } else if (!request.body.path) {
      return (0, _errorResponse.ErrorResponse)('Missing param: path', 3016, 400, response);
    } else if (!request.body.path.match(/^\/.+/)) {
      (0, _logger.log)('wazuh-api:makeRequest', 'Request path is not valid.'); //Path doesn't start with '/'

      return (0, _errorResponse.ErrorResponse)('Request path is not valid.', 3015, 400, response);
    } else {
      return this.makeRequest(context, request.body.method, request.body.path, request.body.body, request.body.id, response);
    }
  }
  /**
   * Get full data on CSV format from a list Wazuh API endpoint
   * @param {Object} ctx
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} csv or ErrorResponse
   */


  async csv(context, request, response) {
    try {
      if (!request.body || !request.body.path) throw new Error('Field path is required');
      if (!request.body.id) throw new Error('Field id is required');
      const filters = Array.isArray(((request || {}).body || {}).filters) ? request.body.filters : [];
      let tmpPath = request.body.path;

      if (tmpPath && typeof tmpPath === 'string') {
        tmpPath = tmpPath[0] === '/' ? tmpPath.substr(1) : tmpPath;
      }

      if (!tmpPath) throw new Error('An error occurred parsing path field');
      (0, _logger.log)('wazuh-api:csv', `Report ${tmpPath}`, 'debug'); // Real limit, regardless the user query

      const params = {
        limit: 500
      };

      if (filters.length) {
        for (const filter of filters) {
          if (!filter.name || !filter.value) continue;
          params[filter.name] = filter.value;
        }
      }

      let itemsArray = [];
      const output = await context.wazuh.api.client.asCurrentUser.request('GET', `/${tmpPath}`, {
        params: params
      }, {
        apiHostID: request.body.id
      });
      const isList = request.body.path.includes('/lists') && request.body.filters && request.body.filters.length && request.body.filters.find(filter => filter._isCDBList);
      const totalItems = (((output || {}).data || {}).data || {}).total_affected_items;

      if (totalItems && !isList) {
        params.offset = 0;
        itemsArray.push(...output.data.data.affected_items);

        while (itemsArray.length < totalItems && params.offset < totalItems) {
          params.offset += params.limit;
          const tmpData = await context.wazuh.api.client.asCurrentUser.request('GET', `/${tmpPath}`, {
            params: params
          }, {
            apiHostID: request.body.id
          });
          itemsArray.push(...tmpData.data.data.affected_items);
        }
      }

      if (totalItems) {
        const {
          path,
          filters
        } = request.body;
        const isArrayOfLists = path.includes('/lists') && !isList;
        const isAgents = path.includes('/agents') && !path.includes('groups');
        const isAgentsOfGroup = path.startsWith('/agents/groups/');
        const isFiles = path.endsWith('/files');
        let fields = Object.keys(output.data.data.affected_items[0]);

        if (isAgents || isAgentsOfGroup) {
          if (isFiles) {
            fields = ['filename', 'hash'];
          } else {
            fields = ['id', 'status', 'name', 'ip', 'group', 'manager', 'node_name', 'dateAdd', 'version', 'lastKeepAlive', 'os.arch', 'os.build', 'os.codename', 'os.major', 'os.minor', 'os.name', 'os.platform', 'os.uname', 'os.version'];
          }
        }

        if (isArrayOfLists) {
          const flatLists = [];

          for (const list of itemsArray) {
            const {
              relative_dirname,
              items
            } = list;
            flatLists.push(...items.map(item => ({
              relative_dirname,
              key: item.key,
              value: item.value
            })));
          }

          fields = ['relative_dirname', 'key', 'value'];
          itemsArray = [...flatLists];
        }

        if (isList) {
          fields = ['key', 'value'];
          itemsArray = output.data.data.affected_items[0].items;
        }

        fields = fields.map(item => ({
          value: item,
          default: '-'
        }));
        const json2csvParser = new _json2csv.Parser({
          fields
        });
        let csv = json2csvParser.parse(itemsArray);

        for (const field of fields) {
          const {
            value
          } = field;

          if (csv.includes(value)) {
            csv = csv.replace(value, _csvKeyEquivalence.KeyEquivalence[value] || value);
          }
        }

        return response.ok({
          headers: {
            'Content-Type': 'text/csv'
          },
          body: csv
        });
      } else if (output && output.data && output.data.data && !output.data.data.total_affected_items) {
        throw new Error('No results');
      } else {
        throw new Error(`An error occurred fetching data from the Wazuh API${output && output.data && output.data.detail ? `: ${output.body.detail}` : ''}`);
      }
    } catch (error) {
      (0, _logger.log)('wazuh-api:csv', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3034, 500, response);
    }
  } // Get de list of available requests in the API


  getRequestList(context, request, response) {
    //Read a static JSON until the api call has implemented
    return response.ok({
      body: _endpoints.default
    });
  }
  /**
   * This get the timestamp field
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} timestamp field or ErrorResponse
   */


  getTimeStamp(context, request, response) {
    try {
      const source = JSON.parse(_fs.default.readFileSync(this.updateRegistry.file, 'utf8'));

      if (source.installationDate && source.lastRestart) {
        (0, _logger.log)('wazuh-api:getTimeStamp', `Installation date: ${source.installationDate}. Last restart: ${source.lastRestart}`, 'debug');
        return response.ok({
          body: {
            installationDate: source.installationDate,
            lastRestart: source.lastRestart
          }
        });
      } else {
        throw new Error('Could not fetch wazuh-version registry');
      }
    } catch (error) {
      (0, _logger.log)('wazuh-api:getTimeStamp', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || 'Could not fetch wazuh-version registry', 4001, 500, response);
    }
  }
  /**
   * This get the extensions
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} extensions object or ErrorResponse
   */


  async setExtensions(context, request, response) {
    try {
      const {
        id,
        extensions
      } = request.body; // Update cluster information in the wazuh-registry.json

      await this.updateRegistry.updateAPIExtensions(id, extensions);
      return response.ok({
        body: {
          statusCode: 200
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:setExtensions', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || 'Could not set extensions', 4001, 500, response);
    }
  }
  /**
   * This get the extensions
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} extensions object or ErrorResponse
   */


  getExtensions(context, request, response) {
    try {
      const source = JSON.parse(_fs.default.readFileSync(this.updateRegistry.file, 'utf8'));
      return response.ok({
        body: {
          extensions: (source.hosts[request.params.id] || {}).extensions || {}
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:getExtensions', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || 'Could not fetch wazuh-version registry', 4001, 500, response);
    }
  }
  /**
   * This get the wazuh setup settings
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} setup info or ErrorResponse
   */


  async getSetupInfo(context, request, response) {
    try {
      const source = JSON.parse(_fs.default.readFileSync(this.updateRegistry.file, 'utf8'));
      return response.ok({
        body: {
          statusCode: 200,
          data: !Object.values(source).length ? '' : source
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:getSetupInfo', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Could not get data from wazuh-version registry due to ${error.message || error}`, 4005, 500, response);
    }
  }
  /**
   * Get basic syscollector information for given agent.
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} Basic syscollector information
   */


  async getSyscollector(context, request, response) {
    try {
      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!request.params || !apiHostID || !request.params.agent) {
        throw new Error('Agent ID and API ID are required');
      }

      const {
        agent
      } = request.params;
      const data = await Promise.all([context.wazuh.api.client.asInternalUser.request('GET', `/syscollector/${agent}/hardware`, {}, {
        apiHostID
      }), context.wazuh.api.client.asInternalUser.request('GET', `/syscollector/${agent}/os`, {}, {
        apiHostID
      })]);
      const result = data.map(item => (item.data || {}).data || []);
      const [hardwareResponse, osResponse] = result; // Fill syscollector object

      const syscollector = {
        hardware: typeof hardwareResponse === 'object' && Object.keys(hardwareResponse).length ? { ...hardwareResponse.affected_items[0]
        } : false,
        os: typeof osResponse === 'object' && Object.keys(osResponse).length ? { ...osResponse.affected_items[0]
        } : false
      };
      return response.ok({
        body: syscollector
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:getSyscollector', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3035, 500, response);
    }
  }

}

exports.WazuhApiCtrl = WazuhApiCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWFwaS50cyJdLCJuYW1lcyI6WyJXYXp1aEFwaUN0cmwiLCJjb25zdHJ1Y3RvciIsIm1hbmFnZUhvc3RzIiwiTWFuYWdlSG9zdHMiLCJ1cGRhdGVSZWdpc3RyeSIsIlVwZGF0ZVJlZ2lzdHJ5IiwiZ2V0VG9rZW4iLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiZm9yY2UiLCJpZEhvc3QiLCJib2R5IiwidXNlcm5hbWUiLCJ3YXp1aCIsInNlY3VyaXR5IiwiZ2V0Q3VycmVudFVzZXIiLCJoZWFkZXJzIiwiY29va2llIiwid3pUb2tlbiIsImRlY29kZWRUb2tlbiIsImV4cGlyYXRpb25UaW1lIiwiZXhwIiwiRGF0ZSIsIm5vdyIsIm9rIiwidG9rZW4iLCJlcnJvciIsIm1lc3NhZ2UiLCJBUElVc2VyQWxsb3dSdW5BcyIsImNhblVzZSIsIkFQSV9VU0VSX1NUQVRVU19SVU5fQVMiLCJFTkFCTEVEIiwiYXBpIiwiY2xpZW50IiwiYXNDdXJyZW50VXNlciIsImF1dGhlbnRpY2F0ZSIsImFzSW50ZXJuYWxVc2VyIiwidGV4dFNlY3VyZSIsInNlcnZlciIsImluZm8iLCJwcm90b2NvbCIsImVycm9yTWVzc2FnZSIsImRhdGEiLCJkZXRhaWwiLCJjaGVja1N0b3JlZEFQSSIsImlkIiwiZ2V0SG9zdEJ5SWQiLCJPYmplY3QiLCJrZXlzIiwibGVuZ3RoIiwiRXJyb3IiLCJyZXNwb25zZU1hbmFnZXJJbmZvIiwiYXBpSG9zdElEIiwiZm9yY2VSZWZyZXNoIiwiY2hlY2tSZXNwb25zZUlzRG93biIsInN0YXR1cyIsImNsdXN0ZXJfaW5mbyIsInJlc3BvbnNlQWdlbnRzIiwicGFyYW1zIiwiYWdlbnRzX2xpc3QiLCJtYW5hZ2VyTmFtZSIsImFmZmVjdGVkX2l0ZW1zIiwibWFuYWdlciIsInJlc3BvbnNlQ2x1c3RlclN0YXR1cyIsImVuYWJsZWQiLCJyZXNwb25zZUNsdXN0ZXJMb2NhbEluZm8iLCJjbHVzdGVyRW5hYmxlZCIsIm5vZGUiLCJjbHVzdGVyIiwidXBkYXRlQ2x1c3RlckluZm8iLCJjb3BpZWQiLCJzZWNyZXQiLCJwYXNzd29yZCIsInN0YXR1c0NvZGUiLCJpZENoYW5nZWQiLCJ1cmwiLCJwb3J0IiwiY29kZSIsImFwaUlzRG93biIsImFwaXMiLCJnZXRIb3N0cyIsInZhbGlkYXRlQ2hlY2tBcGlQYXJhbXMiLCJpbmNsdWRlcyIsImNoZWNrQVBJIiwiYXBpQXZhaWxhYmxlIiwib3B0aW9ucyIsInJlc3BvbnNlQ2x1c3RlciIsImFwaVVzZXJBbGxvd1J1bkFzIiwiQUxMX0RJU0FCTEVEIiwicmVzcG9uc2VBcGlVc2VyQWxsb3dSdW5BcyIsImFsbG93X3J1bl9hcyIsInJ1bl9hcyIsIlVTRVJfTk9UX0FMTE9XRUQiLCJIT1NUX0RJU0FCTEVEIiwiQ2FjaGVJbk1lbW9yeUFQSVVzZXJBbGxvd1J1bkFzIiwic2V0IiwicmVzcG9uc2VDbHVzdGVyTG9jYWwiLCJzb2NrZXRFcnJvckNvZGVzIiwiaXNEb3duIiwiY2hlY2tEYWVtb25zIiwicGF0aCIsImRhZW1vbnMiLCJpc0NsdXN0ZXIiLCJ3YXp1aGRiRXhpc3RzIiwiZXhlY2QiLCJtb2R1bGVzZCIsIndhenVoZGIiLCJjbHVzdGVyZCIsImlzVmFsaWQiLCJQcm9taXNlIiwicmVqZWN0Iiwic2xlZXAiLCJ0aW1lTXMiLCJyZXNvbHZlIiwic2V0VGltZW91dCIsInNob3VsZEtlZXBBcnJheUFzSXQiLCJtZXRob2QiLCJpc0FnZW50c1Jlc3RhcnQiLCJpc0FjdGl2ZVJlc3BvbnNlIiwic3RhcnRzV2l0aCIsImlzQWRkaW5nQWdlbnRzVG9Hcm91cCIsIm1ha2VSZXF1ZXN0IiwiZGV2VG9vbHMiLCJvcmlnaW4iLCJkZWxheSIsInN0YXJ0QXQiLCJydW4iLCJjaGVjayIsImRhdGFQcm9wZXJ0aWVzIiwia2V5IiwiQXJyYXkiLCJpc0FycmF5Iiwiam9pbiIsInJlc3BvbnNlVG9rZW4iLCJyZXNwb25zZUlzRG93biIsInJlc3BvbnNlQm9keSIsInJlc3BvbnNlRXJyb3IiLCJlcnJvck1zZyIsIkFwaUVycm9yRXF1aXZhbGVuY2UiLCJyZXF1ZXN0QXBpIiwiaWRBcGkiLCJtYXRjaCIsImNzdiIsImZpbHRlcnMiLCJ0bXBQYXRoIiwic3Vic3RyIiwibGltaXQiLCJmaWx0ZXIiLCJuYW1lIiwidmFsdWUiLCJpdGVtc0FycmF5Iiwib3V0cHV0IiwiaXNMaXN0IiwiZmluZCIsIl9pc0NEQkxpc3QiLCJ0b3RhbEl0ZW1zIiwidG90YWxfYWZmZWN0ZWRfaXRlbXMiLCJvZmZzZXQiLCJwdXNoIiwidG1wRGF0YSIsImlzQXJyYXlPZkxpc3RzIiwiaXNBZ2VudHMiLCJpc0FnZW50c09mR3JvdXAiLCJpc0ZpbGVzIiwiZW5kc1dpdGgiLCJmaWVsZHMiLCJmbGF0TGlzdHMiLCJsaXN0IiwicmVsYXRpdmVfZGlybmFtZSIsIml0ZW1zIiwibWFwIiwiaXRlbSIsImRlZmF1bHQiLCJqc29uMmNzdlBhcnNlciIsIlBhcnNlciIsInBhcnNlIiwiZmllbGQiLCJyZXBsYWNlIiwiS2V5RXF1aXZhbGVuY2UiLCJnZXRSZXF1ZXN0TGlzdCIsImFwaVJlcXVlc3RMaXN0IiwiZ2V0VGltZVN0YW1wIiwic291cmNlIiwiSlNPTiIsImZzIiwicmVhZEZpbGVTeW5jIiwiZmlsZSIsImluc3RhbGxhdGlvbkRhdGUiLCJsYXN0UmVzdGFydCIsInNldEV4dGVuc2lvbnMiLCJleHRlbnNpb25zIiwidXBkYXRlQVBJRXh0ZW5zaW9ucyIsImdldEV4dGVuc2lvbnMiLCJob3N0cyIsImdldFNldHVwSW5mbyIsInZhbHVlcyIsImdldFN5c2NvbGxlY3RvciIsImFnZW50IiwiYWxsIiwicmVzdWx0IiwiaGFyZHdhcmVSZXNwb25zZSIsIm9zUmVzcG9uc2UiLCJzeXNjb2xsZWN0b3IiLCJoYXJkd2FyZSIsIm9zIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBYUE7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBRUE7O0FBQ0E7Ozs7OztBQUVPLE1BQU1BLFlBQU4sQ0FBbUI7QUFJeEJDLEVBQUFB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LENBQUNBLElBQUksQ0FBQ2pJLElBQUwsSUFBYSxFQUFkLEVBQWtCQSxJQUFsQixJQUEwQixFQUEzQyxDQUFmO0FBQ0EsWUFBTSxDQUFDOEosZ0JBQUQsRUFBbUJDLFVBQW5CLElBQWlDRixNQUF2QyxDQWRFLENBZ0JGOztBQUNBLFlBQU1HLFlBQVksR0FBRztBQUNuQkMsUUFBQUEsUUFBUSxFQUNOLE9BQU9ILGdCQUFQLEtBQTRCLFFBQTVCLElBQXdDekosTUFBTSxDQUFDQyxJQUFQLENBQVl3SixnQkFBWixFQUE4QnZKLE1BQXRFLEdBQ0ksRUFBRSxHQUFHdUosZ0JBQWdCLENBQUMzSSxjQUFqQixDQUFnQyxDQUFoQztBQUFMLFNBREosR0FFSSxLQUphO0FBS25CK0ksUUFBQUEsRUFBRSxFQUNBLE9BQU9ILFVBQVAsS0FBc0IsUUFBdEIsSUFBa0MxSixNQUFNLENBQUNDLElBQVAsQ0FBWXlKLFVBQVosRUFBd0J4SixNQUExRCxHQUNJLEVBQUUsR0FBR3dKLFVBQVUsQ0FBQzVJLGNBQVgsQ0FBMEIsQ0FBMUI7QUFBTCxTQURKLEdBRUk7QUFSYSxPQUFyQjtBQVdBLGFBQU9yRCxRQUFRLENBQUNnQixFQUFULENBQVk7QUFDakJiLFFBQUFBLElBQUksRUFBRStMO0FBRFcsT0FBWixDQUFQO0FBR0QsS0EvQkQsQ0ErQkUsT0FBT2hMLEtBQVAsRUFBYztBQUNkLHVCQUFJLDJCQUFKLEVBQWlDQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQWxEO0FBQ0EsYUFBTyxrQ0FBY0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUEvQixFQUFzQyxJQUF0QyxFQUE0QyxHQUE1QyxFQUFpRGxCLFFBQWpELENBQVA7QUFDRDtBQUNGOztBQXovQnVCIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIENsYXNzIGZvciBXYXp1aC1BUEkgZnVuY3Rpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMSBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG4vLyBSZXF1aXJlIHNvbWUgbGlicmFyaWVzXG5pbXBvcnQgeyBFcnJvclJlc3BvbnNlIH0gZnJvbSAnLi4vbGliL2Vycm9yLXJlc3BvbnNlJztcbmltcG9ydCB7IFBhcnNlciB9IGZyb20gJ2pzb24yY3N2JztcbmltcG9ydCB7IGxvZyB9IGZyb20gJy4uL2xpYi9sb2dnZXInO1xuaW1wb3J0IHsgS2V5RXF1aXZhbGVuY2UgfSBmcm9tICcuLi8uLi9jb21tb24vY3N2LWtleS1lcXVpdmFsZW5jZSc7XG5pbXBvcnQgeyBBcGlFcnJvckVxdWl2YWxlbmNlIH0gZnJvbSAnLi4vbGliL2FwaS1lcnJvcnMtZXF1aXZhbGVuY2UnO1xuaW1wb3J0IGFwaVJlcXVlc3RMaXN0IGZyb20gJy4uLy4uL2NvbW1vbi9hcGktaW5mby9lbmRwb2ludHMnO1xuaW1wb3J0IHsgYWRkSm9iVG9RdWV1ZSB9IGZyb20gJy4uL3N0YXJ0L3F1ZXVlJztcbmltcG9ydCBmcyBmcm9tICdmcyc7XG5pbXBvcnQgeyBNYW5hZ2VIb3N0cyB9IGZyb20gJy4uL2xpYi9tYW5hZ2UtaG9zdHMnO1xuaW1wb3J0IHsgVXBkYXRlUmVnaXN0cnkgfSBmcm9tICcuLi9saWIvdXBkYXRlLXJlZ2lzdHJ5JztcbmltcG9ydCBqd3REZWNvZGUgZnJvbSAnand0LWRlY29kZSc7XG5pbXBvcnQgeyBLaWJhbmFSZXF1ZXN0LCBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIEtpYmFuYVJlc3BvbnNlRmFjdG9yeSB9IGZyb20gJ3NyYy9jb3JlL3NlcnZlcic7XG5pbXBvcnQgeyBBUElVc2VyQWxsb3dSdW5BcywgQ2FjaGVJbk1lbW9yeUFQSVVzZXJBbGxvd1J1bkFzLCBBUElfVVNFUl9TVEFUVVNfUlVOX0FTIH0gZnJvbSAnLi4vbGliL2NhY2hlLWFwaS11c2VyLWhhcy1ydW4tYXMnO1xuaW1wb3J0IHsgZ2V0Q29va2llVmFsdWVCeU5hbWUgfSBmcm9tICcuLi9saWIvY29va2llJztcblxuZXhwb3J0IGNsYXNzIFdhenVoQXBpQ3RybCB7XG4gIG1hbmFnZUhvc3RzOiBNYW5hZ2VIb3N0c1xuICB1cGRhdGVSZWdpc3RyeTogVXBkYXRlUmVnaXN0cnlcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICAvLyB0aGlzLm1vbml0b3JpbmdJbnN0YW5jZSA9IG5ldyBNb25pdG9yaW5nKHNlcnZlciwgdHJ1ZSk7XG4gICAgdGhpcy5tYW5hZ2VIb3N0cyA9IG5ldyBNYW5hZ2VIb3N0cygpO1xuICAgIHRoaXMudXBkYXRlUmVnaXN0cnkgPSBuZXcgVXBkYXRlUmVnaXN0cnkoKTtcbiAgfVxuXG4gIGFzeW5jIGdldFRva2VuKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IGZvcmNlLCBpZEhvc3QgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIGNvbnN0IHsgdXNlcm5hbWUgfSA9IGF3YWl0IGNvbnRleHQud2F6dWguc2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCk7XG4gICAgICBpZiAoIWZvcmNlICYmIHJlcXVlc3QuaGVhZGVycy5jb29raWUgJiYgdXNlcm5hbWUgPT09IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei11c2VyJykgJiYgaWRIb3N0ID09PSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCd3ei1hcGknKSkge1xuICAgICAgICBjb25zdCB3elRva2VuID0gZ2V0Q29va2llVmFsdWVCeU5hbWUocmVxdWVzdC5oZWFkZXJzLmNvb2tpZSwgJ3d6LXRva2VuJyk7XG4gICAgICAgIGlmICh3elRva2VuKSB7XG4gICAgICAgICAgdHJ5IHsgLy8gaWYgdGhlIGN1cnJlbnQgdG9rZW4gaXMgbm90IGEgdmFsaWQgand0IHRva2VuIHdlIGFzayBmb3IgYSBuZXcgb25lXG4gICAgICAgICAgICBjb25zdCBkZWNvZGVkVG9rZW4gPSBqd3REZWNvZGUod3pUb2tlbik7XG4gICAgICAgICAgICBjb25zdCBleHBpcmF0aW9uVGltZSA9IChkZWNvZGVkVG9rZW4uZXhwIC0gKERhdGUubm93KCkgLyAxMDAwKSk7XG4gICAgICAgICAgICBpZiAod3pUb2tlbiAmJiBleHBpcmF0aW9uVGltZSA+IDApIHtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICAgICAgICBib2R5OiB7IHRva2VuOiB3elRva2VuIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgIGxvZygnd2F6dWgtYXBpOmdldFRva2VuJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICBsZXQgdG9rZW47XG4gICAgICBpZiAoYXdhaXQgQVBJVXNlckFsbG93UnVuQXMuY2FuVXNlKGlkSG9zdCkgPT0gQVBJX1VTRVJfU1RBVFVTX1JVTl9BUy5FTkFCTEVEKSB7XG4gICAgICAgIHRva2VuID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIuYXV0aGVudGljYXRlKGlkSG9zdCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0b2tlbiA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5hdXRoZW50aWNhdGUoaWRIb3N0KTtcbiAgICAgIH07XG5cbiAgICAgIGxldCB0ZXh0U2VjdXJlPScnO1xuICAgICAgaWYoY29udGV4dC53YXp1aC5zZXJ2ZXIuaW5mby5wcm90b2NvbCA9PT0gJ2h0dHBzJyl7XG4gICAgICAgIHRleHRTZWN1cmUgPSAnO1NlY3VyZSc7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAnc2V0LWNvb2tpZSc6IFtcbiAgICAgICAgICAgIGB3ei10b2tlbj0ke3Rva2VufTtQYXRoPS87SHR0cE9ubHkke3RleHRTZWN1cmV9YCxcbiAgICAgICAgICAgIGB3ei11c2VyPSR7dXNlcm5hbWV9O1BhdGg9LztIdHRwT25seSR7dGV4dFNlY3VyZX1gLFxuICAgICAgICAgICAgYHd6LWFwaT0ke2lkSG9zdH07UGF0aD0vO0h0dHBPbmx5YCxcbiAgICAgICAgICBdLFxuICAgICAgICB9LFxuICAgICAgICBib2R5OiB7IHRva2VuIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBjb25zdCBlcnJvck1lc3NhZ2UgPSAoKGVycm9yLnJlc3BvbnNlIHx8IHt9KS5kYXRhIHx8IHt9KS5kZXRhaWwgfHwgZXJyb3IubWVzc2FnZSB8fCBlcnJvcjtcbiAgICAgIGxvZygnd2F6dWgtYXBpOmdldFRva2VuJywgZXJyb3JNZXNzYWdlKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICBgRXJyb3IgZ2V0dGluZyB0aGUgYXV0aG9yaXphdGlvbiB0b2tlbjogJHtlcnJvck1lc3NhZ2V9YCxcbiAgICAgICAgMzAwMCxcbiAgICAgICAgNTAwLFxuICAgICAgICByZXNwb25zZVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyBpZiB0aGUgd2F6dWgtYXBpIGNvbmZpZ3VyYXRpb24gaXMgd29ya2luZ1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gc3RhdHVzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjaGVja1N0b3JlZEFQSShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgLy8gR2V0IGNvbmZpZyBmcm9tIHdhenVoLnltbFxuICAgICAgY29uc3QgaWQgPSByZXF1ZXN0LmJvZHkuaWQ7XG4gICAgICBjb25zdCBhcGkgPSBhd2FpdCB0aGlzLm1hbmFnZUhvc3RzLmdldEhvc3RCeUlkKGlkKTtcbiAgICAgIC8vIENoZWNrIE1hbmFnZSBIb3N0c1xuICAgICAgaWYgKCFPYmplY3Qua2V5cyhhcGkpLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NvdWxkIG5vdCBmaW5kIFdhenVoIEFQSSBlbnRyeSBvbiB3YXp1aC55bWwnKTtcbiAgICAgIH1cblxuICAgICAgbG9nKCd3YXp1aC1hcGk6Y2hlY2tTdG9yZWRBUEknLCBgJHtpZH0gZXhpc3RzYCwgJ2RlYnVnJyk7XG5cbiAgICAgIC8vIEZldGNoIG5lZWRlZCBpbmZvcm1hdGlvbiBhYm91dCB0aGUgY2x1c3RlciBhbmQgdGhlIG1hbmFnZXIgaXRzZWxmXG4gICAgICBjb25zdCByZXNwb25zZU1hbmFnZXJJbmZvID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICdnZXQnLFxuICAgICAgICBgL21hbmFnZXIvaW5mb2AsXG4gICAgICAgIHt9LFxuICAgICAgICB7IGFwaUhvc3RJRDogaWQsIGZvcmNlUmVmcmVzaDogdHJ1ZSB9XG4gICAgICApO1xuXG4gICAgICAvLyBMb29rIGZvciBzb2NrZXQtcmVsYXRlZCBlcnJvcnNcbiAgICAgIGlmICh0aGlzLmNoZWNrUmVzcG9uc2VJc0Rvd24ocmVzcG9uc2VNYW5hZ2VySW5mbykpIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgYEVSUk9SMzA5OSAtICR7cmVzcG9uc2VNYW5hZ2VySW5mby5kYXRhLmRldGFpbCB8fCAnV2F6dWggbm90IHJlYWR5IHlldCd9YCxcbiAgICAgICAgICAzMDk5LFxuICAgICAgICAgIDUwMCxcbiAgICAgICAgICByZXNwb25zZVxuICAgICAgICApO1xuICAgICAgfVxuXG4gICAgICAvLyBJZiB3ZSBoYXZlIGEgdmFsaWQgcmVzcG9uc2UgZnJvbSB0aGUgV2F6dWggQVBJXG4gICAgICBpZiAocmVzcG9uc2VNYW5hZ2VySW5mby5zdGF0dXMgPT09IDIwMCAmJiByZXNwb25zZU1hbmFnZXJJbmZvLmRhdGEpIHtcbiAgICAgICAgLy8gQ2xlYXIgYW5kIHVwZGF0ZSBjbHVzdGVyIGluZm9ybWF0aW9uIGJlZm9yZSBiZWluZyBzZW50IGJhY2sgdG8gZnJvbnRlbmRcbiAgICAgICAgZGVsZXRlIGFwaS5jbHVzdGVyX2luZm87XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlQWdlbnRzID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9hZ2VudHNgLFxuICAgICAgICAgIHsgcGFyYW1zOiB7IGFnZW50c19saXN0OiAnMDAwJyB9IH0sXG4gICAgICAgICAgeyBhcGlIb3N0SUQ6IGlkIH1cbiAgICAgICAgKTtcblxuICAgICAgICBpZiAocmVzcG9uc2VBZ2VudHMuc3RhdHVzID09PSAyMDApIHtcbiAgICAgICAgICBjb25zdCBtYW5hZ2VyTmFtZSA9IHJlc3BvbnNlQWdlbnRzLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXS5tYW5hZ2VyO1xuXG4gICAgICAgICAgY29uc3QgcmVzcG9uc2VDbHVzdGVyU3RhdHVzID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgIGAvY2x1c3Rlci9zdGF0dXNgLFxuICAgICAgICAgICAge30sXG4gICAgICAgICAgICB7IGFwaUhvc3RJRDogaWQgfVxuICAgICAgICAgICk7XG4gICAgICAgICAgaWYgKHJlc3BvbnNlQ2x1c3RlclN0YXR1cy5zdGF0dXMgPT09IDIwMCkge1xuICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ2x1c3RlclN0YXR1cy5kYXRhLmRhdGEuZW5hYmxlZCA9PT0gJ3llcycpIHtcbiAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2VDbHVzdGVyTG9jYWxJbmZvID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICAgICAgYC9jbHVzdGVyL2xvY2FsL2luZm9gLFxuICAgICAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgICAgIHsgYXBpSG9zdElEOiBpZCB9XG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZUNsdXN0ZXJMb2NhbEluZm8uc3RhdHVzID09PSAyMDApIHtcbiAgICAgICAgICAgICAgICBjb25zdCBjbHVzdGVyRW5hYmxlZCA9IHJlc3BvbnNlQ2x1c3RlclN0YXR1cy5kYXRhLmRhdGEuZW5hYmxlZCA9PT0gJ3llcyc7XG4gICAgICAgICAgICAgICAgYXBpLmNsdXN0ZXJfaW5mbyA9IHtcbiAgICAgICAgICAgICAgICAgIHN0YXR1czogY2x1c3RlckVuYWJsZWQgPyAnZW5hYmxlZCcgOiAnZGlzYWJsZWQnLFxuICAgICAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgICAgICBub2RlOiByZXNwb25zZUNsdXN0ZXJMb2NhbEluZm8uZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLm5vZGUsXG4gICAgICAgICAgICAgICAgICBjbHVzdGVyOiBjbHVzdGVyRW5hYmxlZFxuICAgICAgICAgICAgICAgICAgICA/IHJlc3BvbnNlQ2x1c3RlckxvY2FsSW5mby5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0uY2x1c3RlclxuICAgICAgICAgICAgICAgICAgICA6ICdEaXNhYmxlZCcsXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgLy8gQ2x1c3RlciBtb2RlIGlzIG5vdCBhY3RpdmVcbiAgICAgICAgICAgICAgYXBpLmNsdXN0ZXJfaW5mbyA9IHtcbiAgICAgICAgICAgICAgICBzdGF0dXM6ICdkaXNhYmxlZCcsXG4gICAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgICAgY2x1c3RlcjogJ0Rpc2FibGVkJyxcbiAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy8gQ2x1c3RlciBtb2RlIGlzIG5vdCBhY3RpdmVcbiAgICAgICAgICAgIGFwaS5jbHVzdGVyX2luZm8gPSB7XG4gICAgICAgICAgICAgIHN0YXR1czogJ2Rpc2FibGVkJyxcbiAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgIGNsdXN0ZXI6ICdEaXNhYmxlZCcsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhcGkuY2x1c3Rlcl9pbmZvKSB7XG4gICAgICAgICAgICAvLyBVcGRhdGUgY2x1c3RlciBpbmZvcm1hdGlvbiBpbiB0aGUgd2F6dWgtcmVnaXN0cnkuanNvblxuICAgICAgICAgICAgYXdhaXQgdGhpcy51cGRhdGVSZWdpc3RyeS51cGRhdGVDbHVzdGVySW5mbyhpZCwgYXBpLmNsdXN0ZXJfaW5mbyk7XG5cbiAgICAgICAgICAgIC8vIEhpZGUgV2F6dWggQVBJIHNlY3JldCwgdXNlcm5hbWUsIHBhc3N3b3JkXG4gICAgICAgICAgICBjb25zdCBjb3BpZWQgPSB7IC4uLmFwaSB9O1xuICAgICAgICAgICAgY29waWVkLnNlY3JldCA9ICcqKioqJztcbiAgICAgICAgICAgIGNvcGllZC5wYXNzd29yZCA9ICcqKioqJztcblxuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICAgICAgICBkYXRhOiBjb3BpZWQsXG4gICAgICAgICAgICAgICAgaWRDaGFuZ2VkOiByZXF1ZXN0LmJvZHkuaWRDaGFuZ2VkIHx8IG51bGwsXG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvLyBJZiB3ZSBoYXZlIGFuIGludmFsaWQgcmVzcG9uc2UgZnJvbSB0aGUgV2F6dWggQVBJXG4gICAgICB0aHJvdyBuZXcgRXJyb3IocmVzcG9uc2VNYW5hZ2VySW5mby5kYXRhLmRldGFpbCB8fCBgJHthcGkudXJsfToke2FwaS5wb3J0fSBpcyB1bnJlYWNoYWJsZWApO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBpZiAoZXJyb3IuY29kZSA9PT0gJ0VQUk9UTycpIHtcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiAyMDAsXG4gICAgICAgICAgICBkYXRhOiB7IHBhc3N3b3JkOiAnKioqKicsIGFwaUlzRG93bjogdHJ1ZSB9LFxuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2UgaWYgKGVycm9yLmNvZGUgPT09ICdFQ09OTlJFRlVTRUQnKSB7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgc3RhdHVzQ29kZTogMjAwLFxuICAgICAgICAgICAgZGF0YTogeyBwYXNzd29yZDogJyoqKionLCBhcGlJc0Rvd246IHRydWUgfSxcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCBhcGlzID0gYXdhaXQgdGhpcy5tYW5hZ2VIb3N0cy5nZXRIb3N0cygpO1xuICAgICAgICAgIGZvciAoY29uc3QgYXBpIG9mIGFwaXMpIHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IGlkID0gT2JqZWN0LmtleXMoYXBpKVswXTtcblxuICAgICAgICAgICAgICBjb25zdCByZXNwb25zZU1hbmFnZXJJbmZvID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICAgICAgYC9tYW5hZ2VyL2luZm9gLFxuICAgICAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgICAgIHsgYXBpSG9zdElEOiBpZCB9XG4gICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgaWYgKHRoaXMuY2hlY2tSZXNwb25zZUlzRG93bihyZXNwb25zZU1hbmFnZXJJbmZvKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgYEVSUk9SMzA5OSAtICR7cmVzcG9uc2UuZGF0YS5kZXRhaWwgfHwgJ1dhenVoIG5vdCByZWFkeSB5ZXQnfWAsXG4gICAgICAgICAgICAgICAgICAzMDk5LFxuICAgICAgICAgICAgICAgICAgNTAwLFxuICAgICAgICAgICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZU1hbmFnZXJJbmZvLnN0YXR1cyA9PT0gMjAwKSB7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5ib2R5LmlkID0gaWQ7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5ib2R5LmlkQ2hhbmdlZCA9IGlkO1xuICAgICAgICAgICAgICAgIHJldHVybiBhd2FpdCB0aGlzLmNoZWNrU3RvcmVkQVBJKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHsgfSAvLyBlc2xpbnQtZGlzYWJsZS1saW5lXG4gICAgICAgICAgfVxuICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgIGxvZygnd2F6dWgtYXBpOmNoZWNrU3RvcmVkQVBJJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgMzAyMCwgNTAwLCByZXNwb25zZSk7XG4gICAgICAgIH1cbiAgICAgICAgbG9nKCd3YXp1aC1hcGk6Y2hlY2tTdG9yZWRBUEknLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgMzAwMiwgNTAwLCByZXNwb25zZSk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgcGVyZm9tcyBhIHZhbGlkYXRpb24gb2YgQVBJIHBhcmFtc1xuICAgKiBAcGFyYW0ge09iamVjdH0gYm9keSBBUEkgcGFyYW1zXG4gICAqL1xuICB2YWxpZGF0ZUNoZWNrQXBpUGFyYW1zKGJvZHkpIHtcbiAgICBpZiAoISgndXNlcm5hbWUnIGluIGJvZHkpKSB7XG4gICAgICByZXR1cm4gJ01pc3NpbmcgcGFyYW06IEFQSSBVU0VSTkFNRSc7XG4gICAgfVxuXG4gICAgaWYgKCEoJ3Bhc3N3b3JkJyBpbiBib2R5KSAmJiAhKCdpZCcgaW4gYm9keSkpIHtcbiAgICAgIHJldHVybiAnTWlzc2luZyBwYXJhbTogQVBJIFBBU1NXT1JEJztcbiAgICB9XG5cbiAgICBpZiAoISgndXJsJyBpbiBib2R5KSkge1xuICAgICAgcmV0dXJuICdNaXNzaW5nIHBhcmFtOiBBUEkgVVJMJztcbiAgICB9XG5cbiAgICBpZiAoISgncG9ydCcgaW4gYm9keSkpIHtcbiAgICAgIHJldHVybiAnTWlzc2luZyBwYXJhbTogQVBJIFBPUlQnO1xuICAgIH1cblxuICAgIGlmICghYm9keS51cmwuaW5jbHVkZXMoJ2h0dHBzOi8vJykgJiYgIWJvZHkudXJsLmluY2x1ZGVzKCdodHRwOi8vJykpIHtcbiAgICAgIHJldHVybiAncHJvdG9jb2xfZXJyb3InO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGNoZWNrIHRoZSB3YXp1aC1hcGkgY29uZmlndXJhdGlvbiByZWNlaXZlZCBpbiB0aGUgUE9TVCBib2R5IHdpbGwgd29ya1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gc3RhdHVzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjaGVja0FQSShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgbGV0IGFwaUF2YWlsYWJsZSA9IG51bGw7XG4gICAgICAvLyBjb25zdCBub3RWYWxpZCA9IHRoaXMudmFsaWRhdGVDaGVja0FwaVBhcmFtcyhyZXF1ZXN0LmJvZHkpO1xuICAgICAgLy8gaWYgKG5vdFZhbGlkKSByZXR1cm4gRXJyb3JSZXNwb25zZShub3RWYWxpZCwgMzAwMywgNTAwLCByZXNwb25zZSk7XG4gICAgICBsb2coJ3dhenVoLWFwaTpjaGVja0FQSScsIGAke3JlcXVlc3QuYm9keS5pZH0gaXMgdmFsaWRgLCAnZGVidWcnKTtcbiAgICAgIC8vIENoZWNrIGlmIGEgV2F6dWggQVBJIGlkIGlzIGdpdmVuIChhbHJlYWR5IHN0b3JlZCBBUEkpXG4gICAgICBjb25zdCBkYXRhID0gYXdhaXQgdGhpcy5tYW5hZ2VIb3N0cy5nZXRIb3N0QnlJZChyZXF1ZXN0LmJvZHkuaWQpO1xuICAgICAgaWYgKGRhdGEpIHtcbiAgICAgICAgYXBpQXZhaWxhYmxlID0gZGF0YTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvZygnd2F6dWgtYXBpOmNoZWNrQVBJJywgYEFQSSAke3JlcXVlc3QuYm9keS5pZH0gbm90IGZvdW5kYCk7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGBUaGUgQVBJICR7cmVxdWVzdC5ib2R5LmlkfSB3YXMgbm90IGZvdW5kYCwgMzAyOSwgNTAwLCByZXNwb25zZSk7XG4gICAgICB9XG4gICAgICBjb25zdCBvcHRpb25zID0geyBhcGlIb3N0SUQ6IHJlcXVlc3QuYm9keS5pZCB9O1xuICAgICAgaWYgKHJlcXVlc3QuYm9keS5mb3JjZVJlZnJlc2gpIHtcbiAgICAgICAgb3B0aW9uc1tcImZvcmNlUmVmcmVzaFwiXSA9IHJlcXVlc3QuYm9keS5mb3JjZVJlZnJlc2g7XG4gICAgICB9XG4gICAgICBsZXQgcmVzcG9uc2VNYW5hZ2VySW5mbztcbiAgICAgIHRyeXtcbiAgICAgICAgcmVzcG9uc2VNYW5hZ2VySW5mbyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgIGAvbWFuYWdlci9pbmZvYCxcbiAgICAgICAgICB7fSxcbiAgICAgICAgICBvcHRpb25zXG4gICAgICAgICk7XG4gICAgICB9Y2F0Y2goZXJyb3Ipe1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgICBgRVJST1IzMDk5IC0gJHtlcnJvci5yZXNwb25zZT8uZGF0YT8uZGV0YWlsIHx8ICdXYXp1aCBub3QgcmVhZHkgeWV0J31gLFxuICAgICAgICAgIDMwOTksXG4gICAgICAgICAgNTAwLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGxvZygnd2F6dWgtYXBpOmNoZWNrQVBJJywgYCR7cmVxdWVzdC5ib2R5LmlkfSBjcmVkZW50aWFscyBhcmUgdmFsaWRgLCAnZGVidWcnKTtcbiAgICAgIGlmIChyZXNwb25zZU1hbmFnZXJJbmZvLnN0YXR1cyA9PT0gMjAwICYmIHJlc3BvbnNlTWFuYWdlckluZm8uZGF0YSkge1xuICAgICAgICBsZXQgcmVzcG9uc2VBZ2VudHMgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdChcbiAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICBgL2FnZW50c2AsXG4gICAgICAgICAgeyBwYXJhbXM6IHsgYWdlbnRzX2xpc3Q6ICcwMDAnIH0gfSxcbiAgICAgICAgICB7IGFwaUhvc3RJRDogcmVxdWVzdC5ib2R5LmlkIH1cbiAgICAgICAgKTtcblxuICAgICAgICBpZiAocmVzcG9uc2VBZ2VudHMuc3RhdHVzID09PSAyMDApIHtcbiAgICAgICAgICBjb25zdCBtYW5hZ2VyTmFtZSA9IHJlc3BvbnNlQWdlbnRzLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXS5tYW5hZ2VyO1xuXG4gICAgICAgICAgbGV0IHJlc3BvbnNlQ2x1c3RlciA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICBgL2NsdXN0ZXIvc3RhdHVzYCxcbiAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgeyBhcGlIb3N0SUQ6IHJlcXVlc3QuYm9keS5pZCB9XG4gICAgICAgICAgKTtcblxuICAgICAgICAgIC8vIENoZWNrIHRoZSBydW5fYXMgZm9yIHRoZSBBUEkgdXNlciBhbmQgdXBkYXRlIGl0XG4gICAgICAgICAgbGV0IGFwaVVzZXJBbGxvd1J1bkFzID0gQVBJX1VTRVJfU1RBVFVTX1JVTl9BUy5BTExfRElTQUJMRUQ7XG4gICAgICAgICAgY29uc3QgcmVzcG9uc2VBcGlVc2VyQWxsb3dSdW5BcyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICBgL3NlY3VyaXR5L3VzZXJzL21lYCxcbiAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgeyBhcGlIb3N0SUQ6IHJlcXVlc3QuYm9keS5pZCB9XG4gICAgICAgICAgKTtcbiAgICAgICAgICBpZiAocmVzcG9uc2VBcGlVc2VyQWxsb3dSdW5Bcy5zdGF0dXMgPT09IDIwMCkge1xuICAgICAgICAgICAgY29uc3QgYWxsb3dfcnVuX2FzID0gcmVzcG9uc2VBcGlVc2VyQWxsb3dSdW5Bcy5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0uYWxsb3dfcnVuX2FzO1xuXG4gICAgICAgICAgICBpZiAoYWxsb3dfcnVuX2FzICYmIGFwaUF2YWlsYWJsZSAmJiBhcGlBdmFpbGFibGUucnVuX2FzKSAvLyBIT1NUIEFORCBVU0VSIEVOQUJMRURcbiAgICAgICAgICAgICAgYXBpVXNlckFsbG93UnVuQXMgPSBBUElfVVNFUl9TVEFUVVNfUlVOX0FTLkVOQUJMRUQ7XG5cbiAgICAgICAgICAgIGVsc2UgaWYgKCFhbGxvd19ydW5fYXMgJiYgYXBpQXZhaWxhYmxlICYmIGFwaUF2YWlsYWJsZS5ydW5fYXMpLy8gSE9TVCBFTkFCTEVEIEFORCBVU0VSIERJU0FCTEVEXG4gICAgICAgICAgICAgIGFwaVVzZXJBbGxvd1J1bkFzID0gQVBJX1VTRVJfU1RBVFVTX1JVTl9BUy5VU0VSX05PVF9BTExPV0VEO1xuXG4gICAgICAgICAgICBlbHNlIGlmIChhbGxvd19ydW5fYXMgJiYgKCAhYXBpQXZhaWxhYmxlIHx8ICFhcGlBdmFpbGFibGUucnVuX2FzICkpIC8vIFVTRVIgRU5BQkxFRCBBTkQgSE9TVCBESVNBQkxFRFxuICAgICAgICAgICAgICBhcGlVc2VyQWxsb3dSdW5BcyA9IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuSE9TVF9ESVNBQkxFRDtcblxuICAgICAgICAgICAgZWxzZSBpZiAoIWFsbG93X3J1bl9hcyAmJiAoICFhcGlBdmFpbGFibGUgfHwgIWFwaUF2YWlsYWJsZS5ydW5fYXMgKSkgLy8gSE9TVCBBTkQgVVNFUiBESVNBQkxFRFxuICAgICAgICAgICAgICBhcGlVc2VyQWxsb3dSdW5BcyA9IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuQUxMX0RJU0FCTEVEO1xuICAgICAgICAgIH1cbiAgICAgICAgICBDYWNoZUluTWVtb3J5QVBJVXNlckFsbG93UnVuQXMuc2V0KFxuICAgICAgICAgICAgcmVxdWVzdC5ib2R5LmlkLFxuICAgICAgICAgICAgYXBpQXZhaWxhYmxlLnVzZXJuYW1lLFxuICAgICAgICAgICAgYXBpVXNlckFsbG93UnVuQXNcbiAgICAgICAgICApO1xuXG4gICAgICAgICAgaWYgKHJlc3BvbnNlQ2x1c3Rlci5zdGF0dXMgPT09IDIwMCkge1xuICAgICAgICAgICAgbG9nKCd3YXp1aC1hcGk6Y2hlY2tTdG9yZWRBUEknLCBgV2F6dWggQVBJIHJlc3BvbnNlIGlzIHZhbGlkYCwgJ2RlYnVnJyk7XG4gICAgICAgICAgICBpZiAocmVzcG9uc2VDbHVzdGVyLmRhdGEuZGF0YS5lbmFibGVkID09PSAneWVzJykge1xuICAgICAgICAgICAgICAvLyBJZiBjbHVzdGVyIG1vZGUgaXMgYWN0aXZlXG4gICAgICAgICAgICAgIGxldCByZXNwb25zZUNsdXN0ZXJMb2NhbCA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgICAgIGAvY2x1c3Rlci9sb2NhbC9pbmZvYCxcbiAgICAgICAgICAgICAgICB7fSxcbiAgICAgICAgICAgICAgICB7IGFwaUhvc3RJRDogcmVxdWVzdC5ib2R5LmlkIH1cbiAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDbHVzdGVyTG9jYWwuc3RhdHVzID09PSAyMDApIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgICAgICAgICBtYW5hZ2VyOiBtYW5hZ2VyTmFtZSxcbiAgICAgICAgICAgICAgICAgICAgbm9kZTogcmVzcG9uc2VDbHVzdGVyTG9jYWwuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLm5vZGUsXG4gICAgICAgICAgICAgICAgICAgIGNsdXN0ZXI6IHJlc3BvbnNlQ2x1c3RlckxvY2FsLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXS5jbHVzdGVyLFxuICAgICAgICAgICAgICAgICAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICAgICAgICAgICAgICAgICAgYWxsb3dfcnVuX2FzOiBhcGlVc2VyQWxsb3dSdW5BcyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIC8vIENsdXN0ZXIgbW9kZSBpcyBub3QgYWN0aXZlXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgICAgICBjbHVzdGVyOiAnRGlzYWJsZWQnLFxuICAgICAgICAgICAgICAgICAgc3RhdHVzOiAnZGlzYWJsZWQnLFxuICAgICAgICAgICAgICAgICAgYWxsb3dfcnVuX2FzOiBhcGlVc2VyQWxsb3dSdW5BcyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1hcGk6Y2hlY2tBUEknLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcblxuICAgICAgaWYgKGVycm9yICYmIGVycm9yLnJlc3BvbnNlICYmIGVycm9yLnJlc3BvbnNlLnN0YXR1cyA9PT0gNDAxKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgIGBVbmF0aG9yaXplZC4gUGxlYXNlIGNoZWNrIEFQSSBjcmVkZW50aWFscy4gJHtlcnJvci5yZXNwb25zZS5kYXRhLm1lc3NhZ2V9YCxcbiAgICAgICAgICA0MDEsXG4gICAgICAgICAgNDAxLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBpZiAoZXJyb3IgJiYgZXJyb3IucmVzcG9uc2UgJiYgZXJyb3IucmVzcG9uc2UuZGF0YSAmJiBlcnJvci5yZXNwb25zZS5kYXRhLmRldGFpbCkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgICBlcnJvci5yZXNwb25zZS5kYXRhLmRldGFpbCxcbiAgICAgICAgICBlcnJvci5yZXNwb25zZS5zdGF0dXMgfHwgNTAwLFxuICAgICAgICAgIGVycm9yLnJlc3BvbnNlLnN0YXR1cyB8fCA1MDAsXG4gICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGlmIChlcnJvci5jb2RlID09PSAnRVBST1RPJykge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgICAnV3JvbmcgcHJvdG9jb2wgYmVpbmcgdXNlZCB0byBjb25uZWN0IHRvIHRoZSBXYXp1aCBBUEknLFxuICAgICAgICAgIDMwMDUsXG4gICAgICAgICAgNTAwLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAzMDA1LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICBjaGVja1Jlc3BvbnNlSXNEb3duKHJlc3BvbnNlKSB7XG4gICAgaWYgKHJlc3BvbnNlLnN0YXR1cyAhPT0gMjAwKSB7XG4gICAgICAvLyBBdm9pZCBcIkVycm9yIGNvbW11bmljYXRpbmcgd2l0aCBzb2NrZXRcIiBsaWtlIGVycm9yc1xuICAgICAgY29uc3Qgc29ja2V0RXJyb3JDb2RlcyA9IFsxMDEzLCAxMDE0LCAxMDE3LCAxMDE4LCAxMDE5XTtcbiAgICAgIGNvbnN0IHN0YXR1cyA9IChyZXNwb25zZS5kYXRhIHx8IHt9KS5zdGF0dXMgfHwgMVxuICAgICAgY29uc3QgaXNEb3duID0gc29ja2V0RXJyb3JDb2Rlcy5pbmNsdWRlcyhzdGF0dXMpO1xuXG4gICAgICBpc0Rvd24gJiYgbG9nKCd3YXp1aC1hcGk6bWFrZVJlcXVlc3QnLCAnV2F6dWggQVBJIGlzIG9ubGluZSBidXQgV2F6dWggaXMgbm90IHJlYWR5IHlldCcpO1xuXG4gICAgICByZXR1cm4gaXNEb3duO1xuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2sgbWFpbiBXYXp1aCBkYWVtb25zIHN0YXR1c1xuICAgKiBAcGFyYW0geyp9IGNvbnRleHQgRW5kcG9pbnQgY29udGV4dFxuICAgKiBAcGFyYW0geyp9IGFwaSBBUEkgZW50cnkgc3RvcmVkIGluIC53YXp1aFxuICAgKiBAcGFyYW0geyp9IHBhdGggT3B0aW9uYWwuIFdhenVoIEFQSSB0YXJnZXQgcGF0aC5cbiAgICovXG4gIGFzeW5jIGNoZWNrRGFlbW9ucyhjb250ZXh0LCBhcGksIHBhdGgpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdChcbiAgICAgICAgJ0dFVCcsXG4gICAgICAgICcvbWFuYWdlci9zdGF0dXMnLFxuICAgICAgICB7fSxcbiAgICAgICAgeyBhcGlIb3N0SUQ6IGFwaS5pZCB9XG4gICAgICApO1xuXG4gICAgICBjb25zdCBkYWVtb25zID0gKCgoKHJlc3BvbnNlIHx8IHt9KS5kYXRhIHx8IHt9KS5kYXRhIHx8IHt9KS5hZmZlY3RlZF9pdGVtcyB8fCBbXSlbMF0gfHwge307XG5cbiAgICAgIGNvbnN0IGlzQ2x1c3RlciA9XG4gICAgICAgICgoYXBpIHx8IHt9KS5jbHVzdGVyX2luZm8gfHwge30pLnN0YXR1cyA9PT0gJ2VuYWJsZWQnICYmXG4gICAgICAgIHR5cGVvZiBkYWVtb25zWyd3YXp1aC1jbHVzdGVyZCddICE9PSAndW5kZWZpbmVkJztcbiAgICAgIGNvbnN0IHdhenVoZGJFeGlzdHMgPSB0eXBlb2YgZGFlbW9uc1snd2F6dWgtZGInXSAhPT0gJ3VuZGVmaW5lZCc7XG5cbiAgICAgIGNvbnN0IGV4ZWNkID0gZGFlbW9uc1snd2F6dWgtZXhlY2QnXSA9PT0gJ3J1bm5pbmcnO1xuICAgICAgY29uc3QgbW9kdWxlc2QgPSBkYWVtb25zWyd3YXp1aC1tb2R1bGVzZCddID09PSAncnVubmluZyc7XG4gICAgICBjb25zdCB3YXp1aGRiID0gd2F6dWhkYkV4aXN0cyA/IGRhZW1vbnNbJ3dhenVoLWRiJ10gPT09ICdydW5uaW5nJyA6IHRydWU7XG4gICAgICBjb25zdCBjbHVzdGVyZCA9IGlzQ2x1c3RlciA/IGRhZW1vbnNbJ3dhenVoLWNsdXN0ZXJkJ10gPT09ICdydW5uaW5nJyA6IHRydWU7XG5cbiAgICAgIGNvbnN0IGlzVmFsaWQgPSBleGVjZCAmJiBtb2R1bGVzZCAmJiB3YXp1aGRiICYmIGNsdXN0ZXJkO1xuXG4gICAgICBpc1ZhbGlkICYmIGxvZygnd2F6dWgtYXBpOmNoZWNrRGFlbW9ucycsIGBXYXp1aCBpcyByZWFkeWAsICdkZWJ1ZycpO1xuXG4gICAgICBpZiAocGF0aCA9PT0gJy9waW5nJykge1xuICAgICAgICByZXR1cm4geyBpc1ZhbGlkIH07XG4gICAgICB9XG5cbiAgICAgIGlmICghaXNWYWxpZCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1dhenVoIG5vdCByZWFkeSB5ZXQnKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1hcGk6Y2hlY2tEYWVtb25zJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIHNsZWVwKHRpbWVNcykge1xuICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZVxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBzZXRUaW1lb3V0KHJlc29sdmUsIHRpbWVNcyk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogSGVscGVyIG1ldGhvZCBmb3IgRGV2IFRvb2xzLlxuICAgKiBodHRwczovL2RvY3VtZW50YXRpb24ud2F6dWguY29tL2N1cnJlbnQvdXNlci1tYW51YWwvYXBpL3JlZmVyZW5jZS5odG1sXG4gICAqIERlcGVuZGluZyBvbiB0aGUgbWV0aG9kIGFuZCB0aGUgcGF0aCBzb21lIHBhcmFtZXRlcnMgc2hvdWxkIGJlIGFuIGFycmF5IG9yIG5vdC5cbiAgICogU2luY2Ugd2UgYWxsb3cgdGhlIHVzZXIgdG8gd3JpdGUgdGhlIHJlcXVlc3QgdXNpbmcgYm90aCBjb21tYS1zZXBhcmF0ZWQgYW5kIGFycmF5IGFzIHdlbGwsXG4gICAqIHdlIG5lZWQgdG8gY2hlY2sgaWYgaXQgc2hvdWxkIGJlIHRyYW5zZm9ybWVkIG9yIG5vdC5cbiAgICogQHBhcmFtIHsqfSBtZXRob2QgVGhlIHJlcXVlc3QgbWV0aG9kXG4gICAqIEBwYXJhbSB7Kn0gcGF0aCBUaGUgV2F6dWggQVBJIHBhdGhcbiAgICovXG4gIHNob3VsZEtlZXBBcnJheUFzSXQobWV0aG9kLCBwYXRoKSB7XG4gICAgLy8gTWV0aG9kcyB0aGF0IHdlIG11c3QgcmVzcGVjdCBhIGRvIG5vdCB0cmFuc2Zvcm0gdGhlbVxuICAgIGNvbnN0IGlzQWdlbnRzUmVzdGFydCA9IG1ldGhvZCA9PT0gJ1BPU1QnICYmIHBhdGggPT09ICcvYWdlbnRzL3Jlc3RhcnQnO1xuICAgIGNvbnN0IGlzQWN0aXZlUmVzcG9uc2UgPSBtZXRob2QgPT09ICdQVVQnICYmIHBhdGguc3RhcnRzV2l0aCgnL2FjdGl2ZS1yZXNwb25zZS8nKTtcbiAgICBjb25zdCBpc0FkZGluZ0FnZW50c1RvR3JvdXAgPSBtZXRob2QgPT09ICdQT1NUJyAmJiBwYXRoLnN0YXJ0c1dpdGgoJy9hZ2VudHMvZ3JvdXAvJyk7XG5cbiAgICAvLyBSZXR1cm5zIHRydWUgb25seSBpZiBvbmUgb2YgdGhlIGFib3ZlIGNvbmRpdGlvbnMgaXMgdHJ1ZVxuICAgIHJldHVybiBpc0FnZW50c1Jlc3RhcnQgfHwgaXNBY3RpdmVSZXNwb25zZSB8fCBpc0FkZGluZ0FnZW50c1RvR3JvdXA7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBwZXJmb3JtcyBhIHJlcXVlc3Qgb3ZlciBXYXp1aCBBUEkgYW5kIHJldHVybnMgaXRzIHJlc3BvbnNlXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBtZXRob2QgTWV0aG9kOiBHRVQsIFBVVCwgUE9TVCwgREVMRVRFXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBwYXRoIEFQSSByb3V0ZVxuICAgKiBAcGFyYW0ge09iamVjdH0gZGF0YSBkYXRhIGFuZCBwYXJhbXMgdG8gcGVyZm9ybSB0aGUgcmVxdWVzdFxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWQgQVBJIGlkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBBUEkgcmVzcG9uc2Ugb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgbWFrZVJlcXVlc3QoY29udGV4dCwgbWV0aG9kLCBwYXRoLCBkYXRhLCBpZCwgcmVzcG9uc2UpIHtcbiAgICBjb25zdCBkZXZUb29scyA9ICEhKGRhdGEgfHwge30pLmRldlRvb2xzO1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBhcGkgPSBhd2FpdCB0aGlzLm1hbmFnZUhvc3RzLmdldEhvc3RCeUlkKGlkKTtcbiAgICAgIGlmIChkZXZUb29scykge1xuICAgICAgICBkZWxldGUgZGF0YS5kZXZUb29scztcbiAgICAgIH1cblxuICAgICAgaWYgKCFPYmplY3Qua2V5cyhhcGkpLmxlbmd0aCkge1xuICAgICAgICBsb2coJ3dhenVoLWFwaTptYWtlUmVxdWVzdCcsICdDb3VsZCBub3QgZ2V0IGhvc3QgY3JlZGVudGlhbHMnKTtcbiAgICAgICAgLy9DYW4gbm90IGdldCBjcmVkZW50aWFscyBmcm9tIHdhenVoLWhvc3RzXG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdDb3VsZCBub3QgZ2V0IGhvc3QgY3JlZGVudGlhbHMnLCAzMDExLCA0MDQsIHJlc3BvbnNlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCFkYXRhKSB7XG4gICAgICAgIGRhdGEgPSB7fTtcbiAgICAgIH07XG5cbiAgICAgIGlmICghZGF0YS5oZWFkZXJzKSB7XG4gICAgICAgIGRhdGEuaGVhZGVycyA9IHt9O1xuICAgICAgfTtcblxuICAgICAgY29uc3Qgb3B0aW9ucyA9IHtcbiAgICAgICAgYXBpSG9zdElEOiBpZFxuICAgICAgfTtcblxuICAgICAgLy8gU2V0IGNvbnRlbnQgdHlwZSBhcHBsaWNhdGlvbi94bWwgaWYgbmVlZGVkXG4gICAgICBpZiAodHlwZW9mIChkYXRhIHx8IHt9KS5ib2R5ID09PSAnc3RyaW5nJyAmJiAoZGF0YSB8fCB7fSkub3JpZ2luID09PSAneG1sZWRpdG9yJykge1xuICAgICAgICBkYXRhLmhlYWRlcnNbJ2NvbnRlbnQtdHlwZSddID0gJ2FwcGxpY2F0aW9uL3htbCc7XG4gICAgICAgIGRlbGV0ZSBkYXRhLm9yaWdpbjtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiAoZGF0YSB8fCB7fSkuYm9keSA9PT0gJ3N0cmluZycgJiYgKGRhdGEgfHwge30pLm9yaWdpbiA9PT0gJ2pzb24nKSB7XG4gICAgICAgIGRhdGEuaGVhZGVyc1snY29udGVudC10eXBlJ10gPSAnYXBwbGljYXRpb24vanNvbic7XG4gICAgICAgIGRlbGV0ZSBkYXRhLm9yaWdpbjtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiAoZGF0YSB8fCB7fSkuYm9keSA9PT0gJ3N0cmluZycgJiYgKGRhdGEgfHwge30pLm9yaWdpbiA9PT0gJ3JhdycpIHtcbiAgICAgICAgZGF0YS5oZWFkZXJzWydjb250ZW50LXR5cGUnXSA9ICdhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0nO1xuICAgICAgICBkZWxldGUgZGF0YS5vcmlnaW47XG4gICAgICB9XG4gICAgICBjb25zdCBkZWxheSA9IChkYXRhIHx8IHt9KS5kZWxheSB8fCAwO1xuICAgICAgaWYgKGRlbGF5KSB7XG4gICAgICAgIGFkZEpvYlRvUXVldWUoe1xuICAgICAgICAgIHN0YXJ0QXQ6IG5ldyBEYXRlKERhdGUubm93KCkgKyBkZWxheSksXG4gICAgICAgICAgcnVuOiBhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0cnl7XG4gICAgICAgICAgICAgIGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QobWV0aG9kLCBwYXRoLCBkYXRhLCBvcHRpb25zKTtcbiAgICAgICAgICAgIH1jYXRjaChlcnJvcil7XG4gICAgICAgICAgICAgIGxvZygncXVldWU6ZGVsYXlBcGlSZXF1ZXN0JyxgQW4gZXJyb3Igb2N1cnJlZCBpbiB0aGUgZGVsYXllZCByZXF1ZXN0OiBcIiR7bWV0aG9kfSAke3BhdGh9XCI6ICR7ZXJyb3IubWVzc2FnZSB8fCBlcnJvcn1gKTtcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7IGVycm9yOiAwLCBtZXNzYWdlOiAnU3VjY2VzcycgfVxuICAgICAgICB9KTtcbiAgICAgIH1cblxuICAgICAgaWYgKHBhdGggPT09ICcvcGluZycpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCBjaGVjayA9IGF3YWl0IHRoaXMuY2hlY2tEYWVtb25zKGNvbnRleHQsIGFwaSwgcGF0aCk7XG4gICAgICAgICAgcmV0dXJuIGNoZWNrO1xuICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgIGNvbnN0IGlzRG93biA9IChlcnJvciB8fCB7fSkuY29kZSA9PT0gJ0VDT05OUkVGVVNFRCc7XG4gICAgICAgICAgaWYgKCFpc0Rvd24pIHtcbiAgICAgICAgICAgIGxvZygnd2F6dWgtYXBpOm1ha2VSZXF1ZXN0JywgJ1dhenVoIEFQSSBpcyBvbmxpbmUgYnV0IFdhenVoIGlzIG5vdCByZWFkeSB5ZXQnKTtcbiAgICAgICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgICAgICBgRVJST1IzMDk5IC0gJHtlcnJvci5tZXNzYWdlIHx8ICdXYXp1aCBub3QgcmVhZHkgeWV0J31gLFxuICAgICAgICAgICAgICAzMDk5LFxuICAgICAgICAgICAgICA1MDAsXG4gICAgICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBsb2coJ3dhenVoLWFwaTptYWtlUmVxdWVzdCcsIGAke21ldGhvZH0gJHtwYXRofWAsICdkZWJ1ZycpO1xuXG4gICAgICAvLyBFeHRyYWN0IGtleXMgZnJvbSBwYXJhbWV0ZXJzXG4gICAgICBjb25zdCBkYXRhUHJvcGVydGllcyA9IE9iamVjdC5rZXlzKGRhdGEpO1xuXG4gICAgICAvLyBUcmFuc2Zvcm0gYXJyYXlzIGludG8gY29tbWEtc2VwYXJhdGVkIHN0cmluZyBpZiBhcHBsaWNhYmxlLlxuICAgICAgLy8gVGhlIHJlYXNvbiBpcyB0aGF0IHdlIGFyZSBhY2NlcHRpbmcgYXJyYXlzIGZvciBjb21tYS1zZXBhcmF0ZWRcbiAgICAgIC8vIHBhcmFtZXRlcnMgaW4gdGhlIERldiBUb29sc1xuICAgICAgaWYgKCF0aGlzLnNob3VsZEtlZXBBcnJheUFzSXQobWV0aG9kLCBwYXRoKSkge1xuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBkYXRhUHJvcGVydGllcykge1xuICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGRhdGFba2V5XSkpIHtcbiAgICAgICAgICAgIGRhdGFba2V5XSA9IGRhdGFba2V5XS5qb2luKCk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICBjb25zdCByZXNwb25zZVRva2VuID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChtZXRob2QsIHBhdGgsIGRhdGEsIG9wdGlvbnMpO1xuICAgICAgY29uc3QgcmVzcG9uc2VJc0Rvd24gPSB0aGlzLmNoZWNrUmVzcG9uc2VJc0Rvd24ocmVzcG9uc2VUb2tlbik7XG4gICAgICBpZiAocmVzcG9uc2VJc0Rvd24pIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgYEVSUk9SMzA5OSAtICR7cmVzcG9uc2UuYm9keS5tZXNzYWdlIHx8ICdXYXp1aCBub3QgcmVhZHkgeWV0J31gLFxuICAgICAgICAgIDMwOTksXG4gICAgICAgICAgNTAwLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBsZXQgcmVzcG9uc2VCb2R5ID0gKHJlc3BvbnNlVG9rZW4gfHwge30pLmRhdGEgfHwge307XG4gICAgICBpZiAoIXJlc3BvbnNlQm9keSkge1xuICAgICAgICByZXNwb25zZUJvZHkgPVxuICAgICAgICAgIHR5cGVvZiByZXNwb25zZUJvZHkgPT09ICdzdHJpbmcnICYmIHBhdGguaW5jbHVkZXMoJy9maWxlcycpICYmIG1ldGhvZCA9PT0gJ0dFVCdcbiAgICAgICAgICAgID8gJyAnXG4gICAgICAgICAgICA6IGZhbHNlO1xuICAgICAgICByZXNwb25zZS5kYXRhID0gcmVzcG9uc2VCb2R5O1xuICAgICAgfVxuICAgICAgY29uc3QgcmVzcG9uc2VFcnJvciA9IHJlc3BvbnNlLnN0YXR1cyAhPT0gMjAwID8gcmVzcG9uc2Uuc3RhdHVzIDogZmFsc2U7XG5cbiAgICAgIGlmICghcmVzcG9uc2VFcnJvciAmJiByZXNwb25zZUJvZHkpIHtcbiAgICAgICAgLy9jbGVhbktleXMocmVzcG9uc2UpO1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHJlc3BvbnNlVG9rZW4uZGF0YVxuICAgICAgICB9KTtcbiAgICAgIH1cblxuICAgICAgaWYgKHJlc3BvbnNlRXJyb3IgJiYgZGV2VG9vbHMpIHtcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiByZXNwb25zZS5kYXRhXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgdGhyb3cgcmVzcG9uc2VFcnJvciAmJiByZXNwb25zZUJvZHkuZGV0YWlsXG4gICAgICAgID8geyBtZXNzYWdlOiByZXNwb25zZUJvZHkuZGV0YWlsLCBjb2RlOiByZXNwb25zZUVycm9yIH1cbiAgICAgICAgOiBuZXcgRXJyb3IoJ1VuZXhwZWN0ZWQgZXJyb3IgZmV0Y2hpbmcgZGF0YSBmcm9tIHRoZSBXYXp1aCBBUEknKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgaWYgKGVycm9yICYmIGVycm9yLnJlc3BvbnNlICYmIGVycm9yLnJlc3BvbnNlLnN0YXR1cyA9PT0gNDAxKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsXG4gICAgICAgICAgZXJyb3IuY29kZSA/IGBXYXp1aCBBUEkgZXJyb3I6ICR7ZXJyb3IuY29kZX1gIDogMzAxMyxcbiAgICAgICAgICA0MDEsXG4gICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGVycm9yTXNnID0gKGVycm9yLnJlc3BvbnNlIHx8IHt9KS5kYXRhIHx8IGVycm9yLm1lc3NhZ2VcbiAgICAgIGxvZygnd2F6dWgtYXBpOm1ha2VSZXF1ZXN0JywgZXJyb3JNc2cgfHwgZXJyb3IpO1xuICAgICAgaWYgKGRldlRvb2xzKSB7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgYm9keTogeyBlcnJvcjogJzMwMTMnLCBtZXNzYWdlOiBlcnJvck1zZyB8fCBlcnJvciB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKChlcnJvciB8fCB7fSkuY29kZSAmJiBBcGlFcnJvckVxdWl2YWxlbmNlW2Vycm9yLmNvZGVdKSB7XG4gICAgICAgICAgZXJyb3IubWVzc2FnZSA9IEFwaUVycm9yRXF1aXZhbGVuY2VbZXJyb3IuY29kZV07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgZXJyb3JNc2cuZGV0YWlsIHx8IGVycm9yLFxuICAgICAgICAgIGVycm9yLmNvZGUgPyBgV2F6dWggQVBJIGVycm9yOiAke2Vycm9yLmNvZGV9YCA6IDMwMTMsXG4gICAgICAgICAgNTAwLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgbWFrZSBhIHJlcXVlc3QgdG8gQVBJXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBhcGkgcmVzcG9uc2Ugb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgcmVxdWVzdEFwaShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICBjb25zdCBpZEFwaSA9IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei1hcGknKTtcbiAgICBpZiAoaWRBcGkgIT09IHJlcXVlc3QuYm9keS5pZCkgeyAvLyBpZiB0aGUgY3VycmVudCB0b2tlbiBiZWxvbmdzIHRvIGEgZGlmZmVyZW50IEFQSSBpZCwgd2UgcmVsb2dpbiB0byBvYnRhaW4gYSBuZXcgdG9rZW5cbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAnc3RhdHVzIGNvZGUgNDAxJyxcbiAgICAgICAgNDAxLFxuICAgICAgICA0MDEsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgICBpZiAoIXJlcXVlc3QuYm9keS5tZXRob2QpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdNaXNzaW5nIHBhcmFtOiBtZXRob2QnLCAzMDE1LCA0MDAsIHJlc3BvbnNlKTtcbiAgICB9IGVsc2UgaWYgKCFyZXF1ZXN0LmJvZHkubWV0aG9kLm1hdGNoKC9eKD86R0VUfFBVVHxQT1NUfERFTEVURSkkLykpIHtcbiAgICAgIGxvZygnd2F6dWgtYXBpOm1ha2VSZXF1ZXN0JywgJ1JlcXVlc3QgbWV0aG9kIGlzIG5vdCB2YWxpZC4nKTtcbiAgICAgIC8vTWV0aG9kIGlzIG5vdCBhIHZhbGlkIEhUVFAgcmVxdWVzdCBtZXRob2RcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdSZXF1ZXN0IG1ldGhvZCBpcyBub3QgdmFsaWQuJywgMzAxNSwgNDAwLCByZXNwb25zZSk7XG4gICAgfSBlbHNlIGlmICghcmVxdWVzdC5ib2R5LnBhdGgpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdNaXNzaW5nIHBhcmFtOiBwYXRoJywgMzAxNiwgNDAwLCByZXNwb25zZSk7XG4gICAgfSBlbHNlIGlmICghcmVxdWVzdC5ib2R5LnBhdGgubWF0Y2goL15cXC8uKy8pKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTptYWtlUmVxdWVzdCcsICdSZXF1ZXN0IHBhdGggaXMgbm90IHZhbGlkLicpO1xuICAgICAgLy9QYXRoIGRvZXNuJ3Qgc3RhcnQgd2l0aCAnLydcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdSZXF1ZXN0IHBhdGggaXMgbm90IHZhbGlkLicsIDMwMTUsIDQwMCwgcmVzcG9uc2UpO1xuICAgIH0gZWxzZSB7XG5cbiAgICAgIHJldHVybiB0aGlzLm1ha2VSZXF1ZXN0KFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICByZXF1ZXN0LmJvZHkubWV0aG9kLFxuICAgICAgICByZXF1ZXN0LmJvZHkucGF0aCxcbiAgICAgICAgcmVxdWVzdC5ib2R5LmJvZHksXG4gICAgICAgIHJlcXVlc3QuYm9keS5pZCxcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIEdldCBmdWxsIGRhdGEgb24gQ1NWIGZvcm1hdCBmcm9tIGEgbGlzdCBXYXp1aCBBUEkgZW5kcG9pbnRcbiAgICogQHBhcmFtIHtPYmplY3R9IGN0eFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gY3N2IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNzdihjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKCFyZXF1ZXN0LmJvZHkgfHwgIXJlcXVlc3QuYm9keS5wYXRoKSB0aHJvdyBuZXcgRXJyb3IoJ0ZpZWxkIHBhdGggaXMgcmVxdWlyZWQnKTtcbiAgICAgIGlmICghcmVxdWVzdC5ib2R5LmlkKSB0aHJvdyBuZXcgRXJyb3IoJ0ZpZWxkIGlkIGlzIHJlcXVpcmVkJyk7XG5cbiAgICAgIGNvbnN0IGZpbHRlcnMgPSBBcnJheS5pc0FycmF5KCgocmVxdWVzdCB8fCB7fSkuYm9keSB8fCB7fSkuZmlsdGVycykgPyByZXF1ZXN0LmJvZHkuZmlsdGVycyA6IFtdO1xuXG4gICAgICBsZXQgdG1wUGF0aCA9IHJlcXVlc3QuYm9keS5wYXRoO1xuXG4gICAgICBpZiAodG1wUGF0aCAmJiB0eXBlb2YgdG1wUGF0aCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgdG1wUGF0aCA9IHRtcFBhdGhbMF0gPT09ICcvJyA/IHRtcFBhdGguc3Vic3RyKDEpIDogdG1wUGF0aDtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0bXBQYXRoKSB0aHJvdyBuZXcgRXJyb3IoJ0FuIGVycm9yIG9jY3VycmVkIHBhcnNpbmcgcGF0aCBmaWVsZCcpO1xuXG4gICAgICBsb2coJ3dhenVoLWFwaTpjc3YnLCBgUmVwb3J0ICR7dG1wUGF0aH1gLCAnZGVidWcnKTtcbiAgICAgIC8vIFJlYWwgbGltaXQsIHJlZ2FyZGxlc3MgdGhlIHVzZXIgcXVlcnlcbiAgICAgIGNvbnN0IHBhcmFtcyA9IHsgbGltaXQ6IDUwMCB9O1xuXG4gICAgICBpZiAoZmlsdGVycy5sZW5ndGgpIHtcbiAgICAgICAgZm9yIChjb25zdCBmaWx0ZXIgb2YgZmlsdGVycykge1xuICAgICAgICAgIGlmICghZmlsdGVyLm5hbWUgfHwgIWZpbHRlci52YWx1ZSkgY29udGludWU7XG4gICAgICAgICAgcGFyYW1zW2ZpbHRlci5uYW1lXSA9IGZpbHRlci52YWx1ZTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBsZXQgaXRlbXNBcnJheSA9IFtdO1xuXG4gICAgICBjb25zdCBvdXRwdXQgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAnR0VUJyxcbiAgICAgICAgYC8ke3RtcFBhdGh9YCxcbiAgICAgICAgeyBwYXJhbXM6IHBhcmFtcyB9LFxuICAgICAgICB7IGFwaUhvc3RJRDogcmVxdWVzdC5ib2R5LmlkIH1cbiAgICAgICk7XG5cbiAgICAgIGNvbnN0IGlzTGlzdCA9IHJlcXVlc3QuYm9keS5wYXRoLmluY2x1ZGVzKCcvbGlzdHMnKSAmJiByZXF1ZXN0LmJvZHkuZmlsdGVycyAmJiByZXF1ZXN0LmJvZHkuZmlsdGVycy5sZW5ndGggJiYgcmVxdWVzdC5ib2R5LmZpbHRlcnMuZmluZChmaWx0ZXIgPT4gZmlsdGVyLl9pc0NEQkxpc3QpO1xuXG4gICAgICBjb25zdCB0b3RhbEl0ZW1zID0gKCgob3V0cHV0IHx8IHt9KS5kYXRhIHx8IHt9KS5kYXRhIHx8IHt9KS50b3RhbF9hZmZlY3RlZF9pdGVtcztcblxuICAgICAgaWYgKHRvdGFsSXRlbXMgJiYgIWlzTGlzdCkge1xuICAgICAgICBwYXJhbXMub2Zmc2V0ID0gMDtcbiAgICAgICAgaXRlbXNBcnJheS5wdXNoKC4uLm91dHB1dC5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXMpO1xuICAgICAgICB3aGlsZSAoaXRlbXNBcnJheS5sZW5ndGggPCB0b3RhbEl0ZW1zICYmIHBhcmFtcy5vZmZzZXQgPCB0b3RhbEl0ZW1zKSB7XG4gICAgICAgICAgcGFyYW1zLm9mZnNldCArPSBwYXJhbXMubGltaXQ7XG4gICAgICAgICAgY29uc3QgdG1wRGF0YSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgIGAvJHt0bXBQYXRofWAsXG4gICAgICAgICAgICB7IHBhcmFtczogcGFyYW1zIH0sXG4gICAgICAgICAgICB7IGFwaUhvc3RJRDogcmVxdWVzdC5ib2R5LmlkIH1cbiAgICAgICAgICApO1xuICAgICAgICAgIGl0ZW1zQXJyYXkucHVzaCguLi50bXBEYXRhLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtcyk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHRvdGFsSXRlbXMpIHtcbiAgICAgICAgY29uc3QgeyBwYXRoLCBmaWx0ZXJzIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICAgIGNvbnN0IGlzQXJyYXlPZkxpc3RzID1cbiAgICAgICAgICBwYXRoLmluY2x1ZGVzKCcvbGlzdHMnKSAmJiAhaXNMaXN0O1xuICAgICAgICBjb25zdCBpc0FnZW50cyA9IHBhdGguaW5jbHVkZXMoJy9hZ2VudHMnKSAmJiAhcGF0aC5pbmNsdWRlcygnZ3JvdXBzJyk7XG4gICAgICAgIGNvbnN0IGlzQWdlbnRzT2ZHcm91cCA9IHBhdGguc3RhcnRzV2l0aCgnL2FnZW50cy9ncm91cHMvJyk7XG4gICAgICAgIGNvbnN0IGlzRmlsZXMgPSBwYXRoLmVuZHNXaXRoKCcvZmlsZXMnKTtcbiAgICAgICAgbGV0IGZpZWxkcyA9IE9iamVjdC5rZXlzKG91dHB1dC5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0pO1xuXG4gICAgICAgIGlmIChpc0FnZW50cyB8fCBpc0FnZW50c09mR3JvdXApIHtcbiAgICAgICAgICBpZiAoaXNGaWxlcykge1xuICAgICAgICAgICAgZmllbGRzID0gWydmaWxlbmFtZScsICdoYXNoJ107XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGZpZWxkcyA9IFtcbiAgICAgICAgICAgICAgJ2lkJyxcbiAgICAgICAgICAgICAgJ3N0YXR1cycsXG4gICAgICAgICAgICAgICduYW1lJyxcbiAgICAgICAgICAgICAgJ2lwJyxcbiAgICAgICAgICAgICAgJ2dyb3VwJyxcbiAgICAgICAgICAgICAgJ21hbmFnZXInLFxuICAgICAgICAgICAgICAnbm9kZV9uYW1lJyxcbiAgICAgICAgICAgICAgJ2RhdGVBZGQnLFxuICAgICAgICAgICAgICAndmVyc2lvbicsXG4gICAgICAgICAgICAgICdsYXN0S2VlcEFsaXZlJyxcbiAgICAgICAgICAgICAgJ29zLmFyY2gnLFxuICAgICAgICAgICAgICAnb3MuYnVpbGQnLFxuICAgICAgICAgICAgICAnb3MuY29kZW5hbWUnLFxuICAgICAgICAgICAgICAnb3MubWFqb3InLFxuICAgICAgICAgICAgICAnb3MubWlub3InLFxuICAgICAgICAgICAgICAnb3MubmFtZScsXG4gICAgICAgICAgICAgICdvcy5wbGF0Zm9ybScsXG4gICAgICAgICAgICAgICdvcy51bmFtZScsXG4gICAgICAgICAgICAgICdvcy52ZXJzaW9uJyxcbiAgICAgICAgICAgIF07XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGlzQXJyYXlPZkxpc3RzKSB7XG4gICAgICAgICAgY29uc3QgZmxhdExpc3RzID0gW107XG4gICAgICAgICAgZm9yIChjb25zdCBsaXN0IG9mIGl0ZW1zQXJyYXkpIHtcbiAgICAgICAgICAgIGNvbnN0IHsgcmVsYXRpdmVfZGlybmFtZSwgaXRlbXMgfSA9IGxpc3Q7XG4gICAgICAgICAgICBmbGF0TGlzdHMucHVzaCguLi5pdGVtcy5tYXAoaXRlbSA9PiAoeyByZWxhdGl2ZV9kaXJuYW1lLCBrZXk6IGl0ZW0ua2V5LCB2YWx1ZTogaXRlbS52YWx1ZSB9KSkpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBmaWVsZHMgPSBbJ3JlbGF0aXZlX2Rpcm5hbWUnLCAna2V5JywgJ3ZhbHVlJ107XG4gICAgICAgICAgaXRlbXNBcnJheSA9IFsuLi5mbGF0TGlzdHNdO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGlzTGlzdCkge1xuICAgICAgICAgIGZpZWxkcyA9IFsna2V5JywgJ3ZhbHVlJ107XG4gICAgICAgICAgaXRlbXNBcnJheSA9IG91dHB1dC5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0uaXRlbXM7XG4gICAgICAgIH1cbiAgICAgICAgZmllbGRzID0gZmllbGRzLm1hcChpdGVtID0+ICh7IHZhbHVlOiBpdGVtLCBkZWZhdWx0OiAnLScgfSkpO1xuXG4gICAgICAgIGNvbnN0IGpzb24yY3N2UGFyc2VyID0gbmV3IFBhcnNlcih7IGZpZWxkcyB9KTtcblxuICAgICAgICBsZXQgY3N2ID0ganNvbjJjc3ZQYXJzZXIucGFyc2UoaXRlbXNBcnJheSk7XG4gICAgICAgIGZvciAoY29uc3QgZmllbGQgb2YgZmllbGRzKSB7XG4gICAgICAgICAgY29uc3QgeyB2YWx1ZSB9ID0gZmllbGQ7XG4gICAgICAgICAgaWYgKGNzdi5pbmNsdWRlcyh2YWx1ZSkpIHtcbiAgICAgICAgICAgIGNzdiA9IGNzdi5yZXBsYWNlKHZhbHVlLCBLZXlFcXVpdmFsZW5jZVt2YWx1ZV0gfHwgdmFsdWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ3RleHQvY3N2JyB9LFxuICAgICAgICAgIGJvZHk6IGNzdlxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSBpZiAob3V0cHV0ICYmIG91dHB1dC5kYXRhICYmIG91dHB1dC5kYXRhLmRhdGEgJiYgIW91dHB1dC5kYXRhLmRhdGEudG90YWxfYWZmZWN0ZWRfaXRlbXMpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdObyByZXN1bHRzJyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEFuIGVycm9yIG9jY3VycmVkIGZldGNoaW5nIGRhdGEgZnJvbSB0aGUgV2F6dWggQVBJJHtvdXRwdXQgJiYgb3V0cHV0LmRhdGEgJiYgb3V0cHV0LmRhdGEuZGV0YWlsID8gYDogJHtvdXRwdXQuYm9keS5kZXRhaWx9YCA6ICcnfWApO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTpjc3YnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDMwMzQsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8vIEdldCBkZSBsaXN0IG9mIGF2YWlsYWJsZSByZXF1ZXN0cyBpbiB0aGUgQVBJXG4gIGdldFJlcXVlc3RMaXN0KGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIC8vUmVhZCBhIHN0YXRpYyBKU09OIHVudGlsIHRoZSBhcGkgY2FsbCBoYXMgaW1wbGVtZW50ZWRcbiAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgYm9keTogYXBpUmVxdWVzdExpc3RcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGdldCB0aGUgdGltZXN0YW1wIGZpZWxkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSB0aW1lc3RhbXAgZmllbGQgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgZ2V0VGltZVN0YW1wKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzb3VyY2UgPSBKU09OLnBhcnNlKGZzLnJlYWRGaWxlU3luYyh0aGlzLnVwZGF0ZVJlZ2lzdHJ5LmZpbGUsICd1dGY4JykpO1xuICAgICAgaWYgKHNvdXJjZS5pbnN0YWxsYXRpb25EYXRlICYmIHNvdXJjZS5sYXN0UmVzdGFydCkge1xuICAgICAgICBsb2coXG4gICAgICAgICAgJ3dhenVoLWFwaTpnZXRUaW1lU3RhbXAnLFxuICAgICAgICAgIGBJbnN0YWxsYXRpb24gZGF0ZTogJHtzb3VyY2UuaW5zdGFsbGF0aW9uRGF0ZX0uIExhc3QgcmVzdGFydDogJHtzb3VyY2UubGFzdFJlc3RhcnR9YCxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgaW5zdGFsbGF0aW9uRGF0ZTogc291cmNlLmluc3RhbGxhdGlvbkRhdGUsXG4gICAgICAgICAgICBsYXN0UmVzdGFydDogc291cmNlLmxhc3RSZXN0YXJ0LFxuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NvdWxkIG5vdCBmZXRjaCB3YXp1aC12ZXJzaW9uIHJlZ2lzdHJ5Jyk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtYXBpOmdldFRpbWVTdGFtcCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgIGVycm9yLm1lc3NhZ2UgfHwgJ0NvdWxkIG5vdCBmZXRjaCB3YXp1aC12ZXJzaW9uIHJlZ2lzdHJ5JyxcbiAgICAgICAgNDAwMSxcbiAgICAgICAgNTAwLFxuICAgICAgICByZXNwb25zZVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBnZXQgdGhlIGV4dGVuc2lvbnNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IGV4dGVuc2lvbnMgb2JqZWN0IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIHNldEV4dGVuc2lvbnMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQsIGV4dGVuc2lvbnMgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIC8vIFVwZGF0ZSBjbHVzdGVyIGluZm9ybWF0aW9uIGluIHRoZSB3YXp1aC1yZWdpc3RyeS5qc29uXG4gICAgICBhd2FpdCB0aGlzLnVwZGF0ZVJlZ2lzdHJ5LnVwZGF0ZUFQSUV4dGVuc2lvbnMoaWQsIGV4dGVuc2lvbnMpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMFxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1hcGk6c2V0RXh0ZW5zaW9ucycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgIGVycm9yLm1lc3NhZ2UgfHwgJ0NvdWxkIG5vdCBzZXQgZXh0ZW5zaW9ucycsXG4gICAgICAgIDQwMDEsXG4gICAgICAgIDUwMCxcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgZ2V0IHRoZSBleHRlbnNpb25zXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBleHRlbnNpb25zIG9iamVjdCBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBnZXRFeHRlbnNpb25zKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzb3VyY2UgPSBKU09OLnBhcnNlKFxuICAgICAgICBmcy5yZWFkRmlsZVN5bmModGhpcy51cGRhdGVSZWdpc3RyeS5maWxlLCAndXRmOCcpXG4gICAgICApO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIGV4dGVuc2lvbnM6IChzb3VyY2UuaG9zdHNbcmVxdWVzdC5wYXJhbXMuaWRdIHx8IHt9KS5leHRlbnNpb25zIHx8IHt9XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTpnZXRFeHRlbnNpb25zJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgZXJyb3IubWVzc2FnZSB8fCAnQ291bGQgbm90IGZldGNoIHdhenVoLXZlcnNpb24gcmVnaXN0cnknLFxuICAgICAgICA0MDAxLFxuICAgICAgICA1MDAsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGdldCB0aGUgd2F6dWggc2V0dXAgc2V0dGluZ3NcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IHNldHVwIGluZm8gb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0U2V0dXBJbmZvKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzb3VyY2UgPSBKU09OLnBhcnNlKGZzLnJlYWRGaWxlU3luYyh0aGlzLnVwZGF0ZVJlZ2lzdHJ5LmZpbGUsICd1dGY4JykpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICBkYXRhOiAhT2JqZWN0LnZhbHVlcyhzb3VyY2UpLmxlbmd0aCA/ICcnIDogc291cmNlXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTpnZXRTZXR1cEluZm8nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICBgQ291bGQgbm90IGdldCBkYXRhIGZyb20gd2F6dWgtdmVyc2lvbiByZWdpc3RyeSBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWAsXG4gICAgICAgIDQwMDUsXG4gICAgICAgIDUwMCxcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIEdldCBiYXNpYyBzeXNjb2xsZWN0b3IgaW5mb3JtYXRpb24gZm9yIGdpdmVuIGFnZW50LlxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gQmFzaWMgc3lzY29sbGVjdG9yIGluZm9ybWF0aW9uXG4gICAqL1xuICBhc3luYyBnZXRTeXNjb2xsZWN0b3IoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGFwaUhvc3RJRCA9IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsJ3d6LWFwaScpO1xuICAgICAgaWYgKCFyZXF1ZXN0LnBhcmFtcyB8fCAhYXBpSG9zdElEIHx8ICFyZXF1ZXN0LnBhcmFtcy5hZ2VudCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0FnZW50IElEIGFuZCBBUEkgSUQgYXJlIHJlcXVpcmVkJyk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHsgYWdlbnQgfSA9IHJlcXVlc3QucGFyYW1zO1xuXG4gICAgICBjb25zdCBkYXRhID0gYXdhaXQgUHJvbWlzZS5hbGwoW1xuICAgICAgICBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdCgnR0VUJywgYC9zeXNjb2xsZWN0b3IvJHthZ2VudH0vaGFyZHdhcmVgLCB7fSwgeyBhcGlIb3N0SUQgfSksXG4gICAgICAgIGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KCdHRVQnLCBgL3N5c2NvbGxlY3Rvci8ke2FnZW50fS9vc2AsIHt9LCB7IGFwaUhvc3RJRCB9KVxuICAgICAgXSk7XG5cbiAgICAgIGNvbnN0IHJlc3VsdCA9IGRhdGEubWFwKGl0ZW0gPT4gKGl0ZW0uZGF0YSB8fCB7fSkuZGF0YSB8fCBbXSk7XG4gICAgICBjb25zdCBbaGFyZHdhcmVSZXNwb25zZSwgb3NSZXNwb25zZV0gPSByZXN1bHQ7XG5cbiAgICAgIC8vIEZpbGwgc3lzY29sbGVjdG9yIG9iamVjdFxuICAgICAgY29uc3Qgc3lzY29sbGVjdG9yID0ge1xuICAgICAgICBoYXJkd2FyZTpcbiAgICAgICAgICB0eXBlb2YgaGFyZHdhcmVSZXNwb25zZSA9PT0gJ29iamVjdCcgJiYgT2JqZWN0LmtleXMoaGFyZHdhcmVSZXNwb25zZSkubGVuZ3RoXG4gICAgICAgICAgICA/IHsgLi4uaGFyZHdhcmVSZXNwb25zZS5hZmZlY3RlZF9pdGVtc1swXSB9XG4gICAgICAgICAgICA6IGZhbHNlLFxuICAgICAgICBvczpcbiAgICAgICAgICB0eXBlb2Ygb3NSZXNwb25zZSA9PT0gJ29iamVjdCcgJiYgT2JqZWN0LmtleXMob3NSZXNwb25zZSkubGVuZ3RoXG4gICAgICAgICAgICA/IHsgLi4ub3NSZXNwb25zZS5hZmZlY3RlZF9pdGVtc1swXSB9XG4gICAgICAgICAgICA6IGZhbHNlLFxuICAgICAgfTtcblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogc3lzY29sbGVjdG9yXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1hcGk6Z2V0U3lzY29sbGVjdG9yJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAzMDM1LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cbn1cbiJdfQ==