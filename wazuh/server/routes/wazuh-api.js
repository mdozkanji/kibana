"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhApiRoutes = WazuhApiRoutes;

var _controllers = require("../controllers");

var _configSchema = require("@kbn/config-schema");

function WazuhApiRoutes(router) {
  const ctrl = new _controllers.WazuhApiCtrl(); // Returns if the wazuh-api configuration is working

  router.post({
    path: '/api/check-stored-api',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        idChanged: _configSchema.schema.maybe(_configSchema.schema.string())
      })
    }
  }, async (context, request, response) => ctrl.checkStoredAPI(context, request, response)); // Check if credentials on POST connect to Wazuh API. Not storing them!
  // Returns if the wazuh-api configuration received in the POST body will work

  router.post({
    path: '/api/check-api',
    validate: {
      body: _configSchema.schema.any({// TODO: not ready
        //id: schema.string(),
        // url: schema.string(),
        // port: schema.number(),
        // username: schema.string(),
        //forceRefresh: schema.boolean({defaultValue:false}),
        // cluster_info: schema.object({
        //   status: schema.string(),
        //   manager: schema.string(),
        //   node: schema.string(),
        //   cluster: schema.string()
        // }),
        // run_as: schema.boolean(),
        // extensions: schema.any(),
        // allow_run_as: schema.number()
      })
    }
  }, async (context, request, response) => ctrl.checkAPI(context, request, response));
  router.post({
    path: '/api/login',
    validate: {
      body: _configSchema.schema.object({
        idHost: _configSchema.schema.string(),
        force: _configSchema.schema.boolean({
          defaultValue: false
        })
      })
    }
  }, async (context, request, response) => ctrl.getToken(context, request, response)); // Returns the request result (With error control)

  router.post({
    path: '/api/request',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        method: _configSchema.schema.string(),
        path: _configSchema.schema.string(),
        body: _configSchema.schema.any()
      })
    }
  }, async (context, request, response) => ctrl.requestApi(context, request, response)); // Returns data from the Wazuh API on CSV readable format

  router.post({
    path: '/api/csv',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        path: _configSchema.schema.string(),
        filters: _configSchema.schema.maybe(_configSchema.schema.any())
      })
    }
  }, async (context, request, response) => ctrl.csv(context, request, response)); // Returns a route list used by the Dev Tools

  router.get({
    path: '/api/routes',
    validate: false
  }, async (context, request, response) => ctrl.getRequestList(context, request, response)); // Useful to check cookie consistence

  router.get({
    path: '/api/timestamp',
    validate: false
  }, async (context, request, response) => ctrl.getTimeStamp(context, request, response));
  router.post({
    path: '/api/extensions',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        extensions: _configSchema.schema.any()
      })
    }
  }, async (context, request, response) => ctrl.setExtensions(context, request, response));
  router.get({
    path: '/api/extensions/{id}',
    validate: {
      params: _configSchema.schema.object({
        id: _configSchema.schema.string()
      })
    }
  }, async (context, request, response) => ctrl.getExtensions(context, request, response)); // Return Wazuh Appsetup info

  router.get({
    path: '/api/setup',
    validate: false
  }, async (context, request, response) => ctrl.getSetupInfo(context, request, response)); // Return basic information of syscollector for given agent

  router.get({
    path: '/api/syscollector/{agent}',
    validate: {
      params: _configSchema.schema.object({
        agent: _configSchema.schema.string()
      })
    }
  }, async (context, request, response) => ctrl.getSyscollector(context, request, response));
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWFwaS50cyJdLCJuYW1lcyI6WyJXYXp1aEFwaVJvdXRlcyIsInJvdXRlciIsImN0cmwiLCJXYXp1aEFwaUN0cmwiLCJwb3N0IiwicGF0aCIsInZhbGlkYXRlIiwiYm9keSIsInNjaGVtYSIsIm9iamVjdCIsImlkIiwic3RyaW5nIiwiaWRDaGFuZ2VkIiwibWF5YmUiLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiY2hlY2tTdG9yZWRBUEkiLCJhbnkiLCJjaGVja0FQSSIsImlkSG9zdCIsImZvcmNlIiwiYm9vbGVhbiIsImRlZmF1bHRWYWx1ZSIsImdldFRva2VuIiwibWV0aG9kIiwicmVxdWVzdEFwaSIsImZpbHRlcnMiLCJjc3YiLCJnZXQiLCJnZXRSZXF1ZXN0TGlzdCIsImdldFRpbWVTdGFtcCIsImV4dGVuc2lvbnMiLCJzZXRFeHRlbnNpb25zIiwicGFyYW1zIiwiZ2V0RXh0ZW5zaW9ucyIsImdldFNldHVwSW5mbyIsImFnZW50IiwiZ2V0U3lzY29sbGVjdG9yIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBRUE7O0FBQ0E7O0FBRU8sU0FBU0EsY0FBVCxDQUF3QkMsTUFBeEIsRUFBeUM7QUFDOUMsUUFBTUMsSUFBSSxHQUFHLElBQUlDLHlCQUFKLEVBQWIsQ0FEOEMsQ0FHOUM7O0FBQ0FGLEVBQUFBLE1BQU0sQ0FBQ0csSUFBUCxDQUFZO0FBQ1ZDLElBQUFBLElBQUksRUFBRSx1QkFESTtBQUVWQyxJQUFBQSxRQUFRLEVBQUU7QUFDUkMsTUFBQUEsSUFBSSxFQUFFQyxxQkFBT0MsTUFBUCxDQUFjO0FBQ2xCQyxRQUFBQSxFQUFFLEVBQUVGLHFCQUFPRyxNQUFQLEVBRGM7QUFFbEJDLFFBQUFBLFNBQVMsRUFBRUoscUJBQU9LLEtBQVAsQ0FBYUwscUJBQU9HLE1BQVAsRUFBYjtBQUZPLE9BQWQ7QUFERTtBQUZBLEdBQVosRUFTRSxPQUFPRyxPQUFQLEVBQWdCQyxPQUFoQixFQUF5QkMsUUFBekIsS0FBc0NkLElBQUksQ0FBQ2UsY0FB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QyxFQWhIOEMsQ0EySDlDOztBQUNBZixFQUFBQSxNQUFNLENBQUM0QixHQUFQLENBQVc7QUFDVHhCLElBQUFBLElBQUksRUFBRSxZQURHO0FBRVRDLElBQUFBLFFBQVEsRUFBRTtBQUZELEdBQVgsRUFJRSxPQUFPUSxPQUFQLEVBQWdCQyxPQUFoQixFQUF5QkMsUUFBekIsS0FBc0NkLElBQUksQ0FBQ2tDLFlBQUwsQ0FBa0J0QixPQUFsQixFQUEyQkMsT0FBM0IsRUFBb0NDLFFBQXBDLENBSnhDLEVBNUg4QyxDQW1JOUM7O0FBQ0FmLEVBQUFBLE1BQU0sQ0FBQzRCLEdBQVAsQ0FBVztBQUNUeEIsSUFBQUEsSUFBSSxFQUFFLDJCQURHO0FBRVRDLElBQUFBLFFBQVEsRUFBRTtBQUNSNEIsTUFBQUEsTUFBTSxFQUFFMUIscUJBQU9DLE1BQVAsQ0FBYztBQUNwQjRCLFFBQUFBLEtBQUssRUFBRTdCLHFCQUFPRyxNQUFQO0FBRGEsT0FBZDtBQURBO0FBRkQsR0FBWCxFQVFFLE9BQU9HLE9BQVAsRUFBZ0JDLE9BQWhCLEVBQXlCQyxRQUF6QixLQUFzQ2QsSUFBSSxDQUFDb0MsZUFBTCxDQUFxQnhCLE9BQXJCLEVBQThCQyxPQUE5QixFQUF1Q0MsUUFBdkMsQ0FSeEM7QUFVRCIsInNvdXJjZXNDb250ZW50IjpbIlxuaW1wb3J0IHsgSVJvdXRlciB9IGZyb20gJ2tpYmFuYS9zZXJ2ZXInO1xuaW1wb3J0IHsgV2F6dWhBcGlDdHJsIH0gZnJvbSAnLi4vY29udHJvbGxlcnMnO1xuaW1wb3J0IHsgc2NoZW1hIH0gZnJvbSAnQGtibi9jb25maWctc2NoZW1hJztcblxuZXhwb3J0IGZ1bmN0aW9uIFdhenVoQXBpUm91dGVzKHJvdXRlcjogSVJvdXRlcikge1xuICBjb25zdCBjdHJsID0gbmV3IFdhenVoQXBpQ3RybCgpO1xuXG4gIC8vIFJldHVybnMgaWYgdGhlIHdhenVoLWFwaSBjb25maWd1cmF0aW9uIGlzIHdvcmtpbmdcbiAgcm91dGVyLnBvc3Qoe1xuICAgIHBhdGg6ICcvYXBpL2NoZWNrLXN0b3JlZC1hcGknLFxuICAgIHZhbGlkYXRlOiB7XG4gICAgICBib2R5OiBzY2hlbWEub2JqZWN0KHtcbiAgICAgICAgaWQ6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgaWRDaGFuZ2VkOiBzY2hlbWEubWF5YmUoc2NoZW1hLnN0cmluZygpKVxuICAgICAgfSlcbiAgICB9XG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmNoZWNrU3RvcmVkQVBJKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIC8vIENoZWNrIGlmIGNyZWRlbnRpYWxzIG9uIFBPU1QgY29ubmVjdCB0byBXYXp1aCBBUEkuIE5vdCBzdG9yaW5nIHRoZW0hXG4gIC8vIFJldHVybnMgaWYgdGhlIHdhenVoLWFwaSBjb25maWd1cmF0aW9uIHJlY2VpdmVkIGluIHRoZSBQT1NUIGJvZHkgd2lsbCB3b3JrXG4gIHJvdXRlci5wb3N0KHtcbiAgICBwYXRoOiAnL2FwaS9jaGVjay1hcGknLFxuICAgIHZhbGlkYXRlOiB7XG4gICAgICBib2R5OiBzY2hlbWEuYW55KHsgLy8gVE9ETzogbm90IHJlYWR5XG4gICAgICAgIC8vaWQ6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgLy8gdXJsOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIC8vIHBvcnQ6IHNjaGVtYS5udW1iZXIoKSxcbiAgICAgICAgLy8gdXNlcm5hbWU6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgLy9mb3JjZVJlZnJlc2g6IHNjaGVtYS5ib29sZWFuKHtkZWZhdWx0VmFsdWU6ZmFsc2V9KSxcbiAgICAgICAgLy8gY2x1c3Rlcl9pbmZvOiBzY2hlbWEub2JqZWN0KHtcbiAgICAgICAgLy8gICBzdGF0dXM6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgLy8gICBtYW5hZ2VyOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIC8vICAgbm9kZTogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICAvLyAgIGNsdXN0ZXI6IHNjaGVtYS5zdHJpbmcoKVxuICAgICAgICAvLyB9KSxcbiAgICAgICAgLy8gcnVuX2FzOiBzY2hlbWEuYm9vbGVhbigpLFxuICAgICAgICAvLyBleHRlbnNpb25zOiBzY2hlbWEuYW55KCksXG4gICAgICAgIC8vIGFsbG93X3J1bl9hczogc2NoZW1hLm51bWJlcigpXG4gICAgICB9KVxuICAgIH1cbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuY2hlY2tBUEkoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG5cbiAgcm91dGVyLnBvc3Qoe1xuICAgIHBhdGg6ICcvYXBpL2xvZ2luJyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgYm9keTogc2NoZW1hLm9iamVjdCh7XG4gICAgICAgIGlkSG9zdDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICBmb3JjZTogc2NoZW1hLmJvb2xlYW4oe2RlZmF1bHRWYWx1ZTogZmFsc2V9KSxcbiAgICAgIH0pXG4gICAgfVxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5nZXRUb2tlbihjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBSZXR1cm5zIHRoZSByZXF1ZXN0IHJlc3VsdCAoV2l0aCBlcnJvciBjb250cm9sKVxuICByb3V0ZXIucG9zdCh7XG4gICAgcGF0aDogJy9hcGkvcmVxdWVzdCcsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGJvZHk6IHNjaGVtYS5vYmplY3Qoe1xuICAgICAgICBpZDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICBtZXRob2Q6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgcGF0aDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICBib2R5OiBzY2hlbWEuYW55KCksXG4gICAgICB9KVxuICAgIH1cbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwucmVxdWVzdEFwaShjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBSZXR1cm5zIGRhdGEgZnJvbSB0aGUgV2F6dWggQVBJIG9uIENTViByZWFkYWJsZSBmb3JtYXRcbiAgcm91dGVyLnBvc3Qoe1xuICAgIHBhdGg6ICcvYXBpL2NzdicsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGJvZHk6IHNjaGVtYS5vYmplY3Qoe1xuICAgICAgICBpZDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICBwYXRoOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIGZpbHRlcnM6IHNjaGVtYS5tYXliZShzY2hlbWEuYW55KCkpXG4gICAgICB9KVxuICAgIH1cbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuY3N2KGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIC8vIFJldHVybnMgYSByb3V0ZSBsaXN0IHVzZWQgYnkgdGhlIERldiBUb29sc1xuICByb3V0ZXIuZ2V0KHtcbiAgICBwYXRoOiAnL2FwaS9yb3V0ZXMnLFxuICAgIHZhbGlkYXRlOiBmYWxzZVxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5nZXRSZXF1ZXN0TGlzdChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBVc2VmdWwgdG8gY2hlY2sgY29va2llIGNvbnNpc3RlbmNlXG4gIHJvdXRlci5nZXQoe1xuICAgIHBhdGg6ICcvYXBpL3RpbWVzdGFtcCcsXG4gICAgdmFsaWRhdGU6IGZhbHNlXG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmdldFRpbWVTdGFtcChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICByb3V0ZXIucG9zdCh7XG4gICAgcGF0aDogJy9hcGkvZXh0ZW5zaW9ucycsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGJvZHk6IHNjaGVtYS5vYmplY3Qoe1xuICAgICAgICBpZDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICBleHRlbnNpb25zOiBzY2hlbWEuYW55KClcbiAgICAgIH0pXG4gICAgfVxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5zZXRFeHRlbnNpb25zKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG5cbiAgcm91dGVyLmdldCh7XG4gICAgcGF0aDogJy9hcGkvZXh0ZW5zaW9ucy97aWR9JyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgcGFyYW1zOiBzY2hlbWEub2JqZWN0KHtcbiAgICAgICAgaWQ6IHNjaGVtYS5zdHJpbmcoKVxuICAgICAgfSlcbiAgICB9XG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmdldEV4dGVuc2lvbnMoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG5cbiAgLy8gUmV0dXJuIFdhenVoIEFwcHNldHVwIGluZm9cbiAgcm91dGVyLmdldCh7XG4gICAgcGF0aDogJy9hcGkvc2V0dXAnLFxuICAgIHZhbGlkYXRlOiBmYWxzZSxcbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuZ2V0U2V0dXBJbmZvKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIC8vIFJldHVybiBiYXNpYyBpbmZvcm1hdGlvbiBvZiBzeXNjb2xsZWN0b3IgZm9yIGdpdmVuIGFnZW50XG4gIHJvdXRlci5nZXQoe1xuICAgIHBhdGg6ICcvYXBpL3N5c2NvbGxlY3Rvci97YWdlbnR9JyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgcGFyYW1zOiBzY2hlbWEub2JqZWN0KHtcbiAgICAgICAgYWdlbnQ6IHNjaGVtYS5zdHJpbmcoKVxuICAgICAgfSlcbiAgICB9XG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmdldFN5c2NvbGxlY3Rvcihjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcbn1cbiJdfQ==