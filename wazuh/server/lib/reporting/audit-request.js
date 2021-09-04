"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getTopFailedSyscalls = exports.getTop3AgentsFailedSyscalls = exports.getTop3AgentsSudoNonSuccessful = void 0;

var _baseQuery = require("./base-query");

var _auditMap = _interopRequireDefault(require("./audit-map"));

var _constants = require("../../../common/constants");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/*
 * Wazuh app - Specific methods to fetch Wazuh Audit data from Elasticsearch
 * Copyright (C) 2015-2021 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

/**
   * Returns top 3 agents that execute sudo commands without success
   * @param {*} context Endpoint context
   * @param {*} gte
   * @param {*} lte
   * @param {*} filters
   * @param {*} pattern
   */
const getTop3AgentsSudoNonSuccessful = async (context, gte, lte, filters, pattern = _constants.WAZUH_ALERTS_PATTERN) => {
  try {
    const base = {};
    Object.assign(base, (0, _baseQuery.Base)(pattern, filters, gte, lte));
    Object.assign(base.aggs, {
      '3': {
        terms: {
          field: 'agent.id',
          size: 3,
          order: {
            _count: 'desc'
          }
        }
      }
    });
    base.query.bool.must.push({
      match_phrase: {
        'data.audit.uid': {
          query: '0'
        }
      }
    });
    base.query.bool.must.push({
      match_phrase: {
        'data.audit.success': {
          query: 'no'
        }
      }
    });
    base.query.bool.must_not.push({
      match_phrase: {
        'data.audit.auid': {
          query: '0'
        }
      }
    });
    const response = await context.core.elasticsearch.client.asCurrentUser.search({
      index: pattern,
      body: base
    });
    const {
      buckets
    } = response.body.aggregations['3'];
    return buckets.map(item => item.key);
  } catch (error) {
    return Promise.reject(error);
  }
};
/**
 * Returns the most failed syscall in the top 3 agents with failed system calls
 * @param {*} context Endpoint context
 * @param {*} gte
 * @param {*} lte
 * @param {*} filters
 * @param {*} pattern
 */


exports.getTop3AgentsSudoNonSuccessful = getTop3AgentsSudoNonSuccessful;

const getTop3AgentsFailedSyscalls = async (context, gte, lte, filters, pattern = _constants.WAZUH_ALERTS_PATTERN) => {
  try {
    const base = {};
    Object.assign(base, (0, _baseQuery.Base)(pattern, filters, gte, lte));
    Object.assign(base.aggs, {
      '3': {
        terms: {
          field: 'agent.id',
          size: 3,
          order: {
            _count: 'desc'
          }
        },
        aggs: {
          '4': {
            terms: {
              field: 'data.audit.syscall',
              size: 1,
              order: {
                _count: 'desc'
              }
            }
          }
        }
      }
    });
    base.query.bool.must.push({
      match_phrase: {
        'data.audit.success': {
          query: 'no'
        }
      }
    });
    const response = await context.core.elasticsearch.client.asCurrentUser.search({
      index: pattern,
      body: base
    });
    const {
      buckets
    } = response.body.aggregations['3'];
    return buckets.map(bucket => {
      try {
        const agent = bucket.key;
        const syscall = {
          id: bucket['4'].buckets[0].key,
          syscall: _auditMap.default[bucket['4'].buckets[0].key] || 'Warning: Unknown system call'
        };
        return {
          agent,
          syscall
        };
      } catch (error) {
        return undefined;
      }
    }).filter(bucket => bucket);
  } catch (error) {
    return Promise.reject(error);
  }
};
/**
 * Returns the top failed syscalls
 * @param {*} context Endpoint context
 * @param {*} gte
 * @param {*} lte
 * @param {*} filters
 * @param {*} pattern
 */


exports.getTop3AgentsFailedSyscalls = getTop3AgentsFailedSyscalls;

const getTopFailedSyscalls = async (context, gte, lte, filters, pattern = _constants.WAZUH_ALERTS_PATTERN) => {
  try {
    const base = {};
    Object.assign(base, (0, _baseQuery.Base)(pattern, filters, gte, lte));
    Object.assign(base.aggs, {
      '2': {
        terms: {
          field: 'data.audit.syscall',
          size: 10,
          order: {
            _count: 'desc'
          }
        }
      }
    });
    base.query.bool.must.push({
      match_phrase: {
        'data.audit.success': {
          query: 'no'
        }
      }
    });
    const response = await context.core.elasticsearch.client.asCurrentUser.search({
      index: pattern,
      body: base
    });
    const {
      buckets
    } = response.body.aggregations['2'];
    return buckets.map(item => ({
      id: item.key,
      syscall: _auditMap.default[item.key]
    }));
  } catch (error) {
    return Promise.reject(error);
  }
};

exports.getTopFailedSyscalls = getTopFailedSyscalls;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImF1ZGl0LXJlcXVlc3QudHMiXSwibmFtZXMiOlsiZ2V0VG9wM0FnZW50c1N1ZG9Ob25TdWNjZXNzZnVsIiwiY29udGV4dCIsImd0ZSIsImx0ZSIsImZpbHRlcnMiLCJwYXR0ZXJuIiwiV0FaVUhfQUxFUlRTX1BBVFRFUk4iLCJiYXNlIiwiT2JqZWN0IiwiYXNzaWduIiwiYWdncyIsInRlcm1zIiwiZmllbGQiLCJzaXplIiwib3JkZXIiLCJfY291bnQiLCJxdWVyeSIsImJvb2wiLCJtdXN0IiwicHVzaCIsIm1hdGNoX3BocmFzZSIsIm11c3Rfbm90IiwicmVzcG9uc2UiLCJjb3JlIiwiZWxhc3RpY3NlYXJjaCIsImNsaWVudCIsImFzQ3VycmVudFVzZXIiLCJzZWFyY2giLCJpbmRleCIsImJvZHkiLCJidWNrZXRzIiwiYWdncmVnYXRpb25zIiwibWFwIiwiaXRlbSIsImtleSIsImVycm9yIiwiUHJvbWlzZSIsInJlamVjdCIsImdldFRvcDNBZ2VudHNGYWlsZWRTeXNjYWxscyIsImJ1Y2tldCIsImFnZW50Iiwic3lzY2FsbCIsImlkIiwiQXVkaXRNYXAiLCJ1bmRlZmluZWQiLCJmaWx0ZXIiLCJnZXRUb3BGYWlsZWRTeXNjYWxscyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQVdBOztBQUNBOztBQUNBOzs7O0FBYkE7Ozs7Ozs7Ozs7OztBQWVBOzs7Ozs7OztBQVFPLE1BQU1BLDhCQUE4QixHQUFHLE9BQzVDQyxPQUQ0QyxFQUU1Q0MsR0FGNEMsRUFHNUNDLEdBSDRDLEVBSTVDQyxPQUo0QyxFQUs1Q0MsT0FBTyxHQUFHQywrQkFMa0MsS0FNekM7QUFDSCxNQUFJO0FBQ0YsVUFBTUMsSUFBSSxHQUFHLEVBQWI7QUFFQUMsSUFBQUEsTUFBTSxDQUFDQyxNQUFQLENBQWNGLElBQWQsRUFBb0IscUJBQUtGLE9BQUwsRUFBY0QsT0FBZCxFQUF1QkYsR0FBdkIsRUFBNEJDLEdBQTVCLENBQXBCO0FBRUFLLElBQUFBLE1BQU0sQ0FBQ0MsTUFBUCxDQUFjRixJQUFJLENB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aUI7QUFFMUJPLE1BQUFBLE9BQU8sRUFBRUUsa0JBQVNWLElBQUksQ0FBQ0MsR0FBZDtBQUZpQixLQUFMLENBQWhCLENBQVA7QUFJRCxHQW5DRCxDQW1DRSxPQUFPQyxLQUFQLEVBQWM7QUFDZCxXQUFPQyxPQUFPLENBQUNDLE1BQVIsQ0FBZUYsS0FBZixDQUFQO0FBQ0Q7QUFDRixDQTdDTSIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBTcGVjaWZpYyBtZXRob2RzIHRvIGZldGNoIFdhenVoIEF1ZGl0IGRhdGEgZnJvbSBFbGFzdGljc2VhcmNoXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMSBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHsgQmFzZSB9IGZyb20gJy4vYmFzZS1xdWVyeSc7XG5pbXBvcnQgQXVkaXRNYXAgZnJvbSAnLi9hdWRpdC1tYXAnO1xuaW1wb3J0IHsgV0FaVUhfQUxFUlRTX1BBVFRFUk4gfSBmcm9tICcuLi8uLi8uLi9jb21tb24vY29uc3RhbnRzJztcblxuLyoqXG4gICAqIFJldHVybnMgdG9wIDMgYWdlbnRzIHRoYXQgZXhlY3V0ZSBzdWRvIGNvbW1hbmRzIHdpdGhvdXQgc3VjY2Vzc1xuICAgKiBAcGFyYW0geyp9IGNvbnRleHQgRW5kcG9pbnQgY29udGV4dFxuICAgKiBAcGFyYW0geyp9IGd0ZVxuICAgKiBAcGFyYW0geyp9IGx0ZVxuICAgKiBAcGFyYW0geyp9IGZpbHRlcnNcbiAgICogQHBhcmFtIHsqfSBwYXR0ZXJuXG4gICAqL1xuZXhwb3J0IGNvbnN0IGdldFRvcDNBZ2VudHNTdWRvTm9uU3VjY2Vzc2Z1bCA9IGFzeW5jIChcbiAgY29udGV4dCxcbiAgZ3RlLFxuICBsdGUsXG4gIGZpbHRlcnMsXG4gIHBhdHRlcm4gPSBXQVpVSF9BTEVSVFNfUEFUVEVSTlxuKSA9PiB7XG4gIHRyeSB7XG4gICAgY29uc3QgYmFzZSA9IHt9O1xuXG4gICAgT2JqZWN0LmFzc2lnbihiYXNlLCBCYXNlKHBhdHRlcm4sIGZpbHRlcnMsIGd0ZSwgbHRlKSk7XG5cbiAgICBPYmplY3QuYXNzaWduKGJhc2UuYWdncywge1xuICAgICAgJzMnOiB7XG4gICAgICAgIHRlcm1zOiB7XG4gICAgICAgICAgZmllbGQ6ICdhZ2VudC5pZCcsXG4gICAgICAgICAgc2l6ZTogMyxcbiAgICAgICAgICBvcmRlcjoge1xuICAgICAgICAgICAgX2NvdW50OiAnZGVzYydcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGJhc2UucXVlcnkuYm9vbC5tdXN0LnB1c2goe1xuICAgICAgbWF0Y2hfcGhyYXNlOiB7XG4gICAgICAgICdkYXRhLmF1ZGl0LnVpZCc6IHtcbiAgICAgICAgICBxdWVyeTogJzAnXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGJhc2UucXVlcnkuYm9vbC5tdXN0LnB1c2goe1xuICAgICAgbWF0Y2hfcGhyYXNlOiB7XG4gICAgICAgICdkYXRhLmF1ZGl0LnN1Y2Nlc3MnOiB7XG4gICAgICAgICAgcXVlcnk6ICdubydcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgYmFzZS5xdWVyeS5ib29sLm11c3Rfbm90LnB1c2goe1xuICAgICAgbWF0Y2hfcGhyYXNlOiB7XG4gICAgICAgICdkYXRhLmF1ZGl0LmF1aWQnOiB7XG4gICAgICAgICAgcXVlcnk6ICcwJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaCh7XG4gICAgICBpbmRleDogcGF0dGVybixcbiAgICAgIGJvZHk6IGJhc2VcbiAgICB9KTtcbiAgICBjb25zdCB7IGJ1Y2tldHMgfSA9IHJlc3BvbnNlLmJvZHkuYWdncmVnYXRpb25zWyczJ107XG4gICAgcmV0dXJuIGJ1Y2tldHMubWFwKGl0ZW0gPT4gaXRlbS5rZXkpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gIH1cbn1cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBtb3N0IGZhaWxlZCBzeXNjYWxsIGluIHRoZSB0b3AgMyBhZ2VudHMgd2l0aCBmYWlsZWQgc3lzdGVtIGNhbGxzXG4gKiBAcGFyYW0geyp9IGNvbnRleHQgRW5kcG9pbnQgY29udGV4dFxuICogQHBhcmFtIHsqfSBndGVcbiAqIEBwYXJhbSB7Kn0gbHRlXG4gKiBAcGFyYW0geyp9IGZpbHRlcnNcbiAqIEBwYXJhbSB7Kn0gcGF0dGVyblxuICovXG5leHBvcnQgY29uc3QgZ2V0VG9wM0FnZW50c0ZhaWxlZFN5c2NhbGxzID0gYXN5bmMgKFxuICBjb250ZXh0LFxuICBndGUsXG4gIGx0ZSxcbiAgZmlsdGVycyxcbiAgcGF0dGVybiA9IFdBWlVIX0FMRVJUU19QQVRURVJOXG4pID0+IHtcbiAgdHJ5IHtcbiAgICBjb25zdCBiYXNlID0ge307XG5cbiAgICBPYmplY3QuYXNzaWduKGJhc2UsIEJhc2UocGF0dGVybiwgZmlsdGVycywgZ3RlLCBsdGUpKTtcblxuICAgIE9iamVjdC5hc3NpZ24oYmFzZS5hZ2dzLCB7XG4gICAgICAnMyc6IHtcbiAgICAgICAgdGVybXM6IHtcbiAgICAgICAgICBmaWVsZDogJ2FnZW50LmlkJyxcbiAgICAgICAgICBzaXplOiAzLFxuICAgICAgICAgIG9yZGVyOiB7XG4gICAgICAgICAgICBfY291bnQ6ICdkZXNjJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgYWdnczoge1xuICAgICAgICAgICc0Jzoge1xuICAgICAgICAgICAgdGVybXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLmF1ZGl0LnN5c2NhbGwnLFxuICAgICAgICAgICAgICBzaXplOiAxLFxuICAgICAgICAgICAgICBvcmRlcjoge1xuICAgICAgICAgICAgICAgIF9jb3VudDogJ2Rlc2MnXG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGJhc2UucXVlcnkuYm9vbC5tdXN0LnB1c2goe1xuICAgICAgbWF0Y2hfcGhyYXNlOiB7XG4gICAgICAgICdkYXRhLmF1ZGl0LnN1Y2Nlc3MnOiB7XG4gICAgICAgICAgcXVlcnk6ICdubydcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5zZWFyY2goe1xuICAgICAgaW5kZXg6IHBhdHRlcm4sXG4gICAgICBib2R5OiBiYXNlXG4gICAgfSk7XG4gICAgY29uc3QgeyBidWNrZXRzIH0gPSByZXNwb25zZS5ib2R5LmFnZ3JlZ2F0aW9uc1snMyddO1xuXG4gICAgcmV0dXJuIGJ1Y2tldHMubWFwKGJ1Y2tldCA9PiB7XG4gICAgICB0cnl7XG4gICAgICAgIGNvbnN0IGFnZW50ID0gYnVja2V0LmtleTtcbiAgICAgICAgY29uc3Qgc3lzY2FsbCA9IHtcbiAgICAgICAgICBpZDogYnVja2V0Wyc0J10uYnVja2V0c1swXS5rZXksXG4gICAgICAgICAgc3lzY2FsbDpcbiAgICAgICAgICAgIEF1ZGl0TWFwW2J1Y2tldFsnNCddLmJ1Y2tldHNbMF0ua2V5XSB8fFxuICAgICAgICAgICAgJ1dhcm5pbmc6IFVua25vd24gc3lzdGVtIGNhbGwnXG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgYWdlbnQsXG4gICAgICAgICAgc3lzY2FsbFxuICAgICAgICB9O1xuICAgICAgfWNhdGNoKGVycm9yKXtcbiAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgIH1cbiAgICB9KS5maWx0ZXIoYnVja2V0ID0+IGJ1Y2tldCk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgfVxufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIHRvcCBmYWlsZWQgc3lzY2FsbHNcbiAqIEBwYXJhbSB7Kn0gY29udGV4dCBFbmRwb2ludCBjb250ZXh0XG4gKiBAcGFyYW0geyp9IGd0ZVxuICogQHBhcmFtIHsqfSBsdGVcbiAqIEBwYXJhbSB7Kn0gZmlsdGVyc1xuICogQHBhcmFtIHsqfSBwYXR0ZXJuXG4gKi9cbmV4cG9ydCBjb25zdCBnZXRUb3BGYWlsZWRTeXNjYWxscyA9IGFzeW5jIChcbiAgY29udGV4dCxcbiAgZ3RlLFxuICBsdGUsXG4gIGZpbHRlcnMsXG4gIHBhdHRlcm4gPSBXQVpVSF9BTEVSVFNfUEFUVEVSTlxuKSA9PiB7XG4gIHRyeSB7XG4gICAgY29uc3QgYmFzZSA9IHt9O1xuXG4gICAgT2JqZWN0LmFzc2lnbihiYXNlLCBCYXNlKHBhdHRlcm4sIGZpbHRlcnMsIGd0ZSwgbHRlKSk7XG5cbiAgICBPYmplY3QuYXNzaWduKGJhc2UuYWdncywge1xuICAgICAgJzInOiB7XG4gICAgICAgIHRlcm1zOiB7XG4gICAgICAgICAgZmllbGQ6ICdkYXRhLmF1ZGl0LnN5c2NhbGwnLFxuICAgICAgICAgIHNpemU6IDEwLFxuICAgICAgICAgIG9yZGVyOiB7XG4gICAgICAgICAgICBfY291bnQ6ICdkZXNjJ1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgYmFzZS5xdWVyeS5ib29sLm11c3QucHVzaCh7XG4gICAgICBtYXRjaF9waHJhc2U6IHtcbiAgICAgICAgJ2RhdGEuYXVkaXQuc3VjY2Vzcyc6IHtcbiAgICAgICAgICBxdWVyeTogJ25vJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaCh7XG4gICAgICBpbmRleDogcGF0dGVybixcbiAgICAgIGJvZHk6IGJhc2VcbiAgICB9KTtcbiAgICBjb25zdCB7IGJ1Y2tldHMgfSA9IHJlc3BvbnNlLmJvZHkuYWdncmVnYXRpb25zWycyJ107XG5cbiAgICByZXR1cm4gYnVja2V0cy5tYXAoaXRlbSA9PiAoe1xuICAgICAgaWQ6IGl0ZW0ua2V5LFxuICAgICAgc3lzY2FsbDogQXVkaXRNYXBbaXRlbS5rZXldXG4gICAgfSkpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gIH1cbn1cbiJdfQ==