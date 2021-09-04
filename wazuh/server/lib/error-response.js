"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ErrorResponse = ErrorResponse;

/*
 * Wazuh app - Generic error response constructor
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
 * Error codes:
 * wazuh-api-elastic 20XX
 * wazuh-api         30XX
 * wazuh-elastic     40XX
 * wazuh-reporting   50XX
 * unknown           1000
 */

/**
 * Returns a suitable error message
 * @param {String} message Error message
 * @param {Number} code Error code
 * @param {Number} statusCode Error status code
 * @returns {Object} Error response object
 */
function ErrorResponse(message = null, code = null, statusCode = null, response) {
  message.includes('password: ') ? message = message.split('password: ')[0] + ' password: ***' : false;
  let filteredMessage = '';

  if (code) {
    const isString = typeof message === 'string';

    if (isString && message === 'socket hang up' && code === 3005) {
      filteredMessage = 'Wrong protocol being used to connect to the Wazuh API';
    } else if (isString && (message.includes('ENOTFOUND') || message.includes('EHOSTUNREACH') || message.includes('EINVAL') || message.includes('EAI_AGAIN')) && code === 3005) {
      filteredMessage = 'Wazuh API is not reachable. Please check your url and port.';
    } else if (isString && message.includes('ECONNREFUSED') && code === 3005) {
      filteredMessage = 'Wazuh API is not reachable. Please check your url and port.';
    } else if (isString && message.toLowerCase().includes('not found') && code === 3002) {
      filteredMessage = 'It seems the selected API was deleted.';
    } else if (isString && message.includes('ENOENT') && message.toLowerCase().includes('no such file or directory') && message.toLowerCase().includes('data') && code === 5029) {
      filteredMessage = 'Reporting was aborted';
    } else if (isString && code === 5029) {
      filteredMessage = `Reporting was aborted (${message})`;
    }
  }

  const statusCodeResponse = statusCode || 500;
  return response.custom({
    statusCode: statusCodeResponse,
    body: {
      message: filteredMessage ? `${code || 1000} - ${filteredMessage}` : typeof message === 'string' ? `${code || 1000} - ${message}` : `${code || 1000} - Unexpected error`,
      code: code || 1000,
      statusCode: statusCodeResponse
    }
  });
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImVycm9yLXJlc3BvbnNlLnRzIl0sIm5hbWVzIjpbIkVycm9yUmVzcG9uc2UiLCJtZXNzYWdlIiwiY29kZSIsInN0YXR1c0NvZGUiLCJyZXNwb25zZSIsImluY2x1ZGVzIiwic3BsaXQiLCJmaWx0ZXJlZE1lc3NhZ2UiLCJpc1N0cmluZyIsInRvTG93ZXJDYXNlIiwic3RhdHVzQ29kZVJlc3BvbnNlIiwiY3VzdG9tIiwiYm9keSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOzs7Ozs7Ozs7Ozs7QUFZQTs7Ozs7Ozs7O0FBUUE7Ozs7Ozs7QUFPTyxTQUFTQSxhQUFULENBQ0xDLE9BQU8sR0FBRyxJQURMLEVBRUxDLElBQUksR0FBRyxJQUZGLEVBR0xDLFVBQVUsR0FBRyxJQUhSLEVBSUxDLFFBSkssRUFLTDtBQUNBSCxFQUFBQSxPQUFPLENBQUNJLFFBQVIsQ0FBaUIsWUFBakIsSUFBaUNKLE9BQU8sR0FBR0EsT0FBTyxDQUFDSyxLQUFSLENBQWMsWUFBZCxFQUE0QixDQUE1QixJQUFpQyxnQkFBNUUsR0FBK0YsS0FBL0Y7QUFDQSxNQUFJQyxlQUFlLEdBQUcsRUFBdEI7O0FBQ0EsTUFBSUwsSUFBSixFQUFVO0FBQ1IsVUFBTU0sUUFBUSxHQUFHLE9BQU9QLE9BQVAsS0FBbUIsUUFBcEM7O0FBQ0EsUUFBSU8sUUFBUSxJQUFJUCxPQUFPLEtBQUssZ0JBQXhCLElBQTRDQyxJQUFJLEtBQUssSUFBekQsRUFBK0Q7QUFDN0RLLE1BQUFBLGVBQWUsR0FBRyx1REFBbEI7QUFDRCxLQUZELE1BRU8sSUFDTEMsUUFBUSxLQUNQUCxPQUFPLENBQUNJLFFBQVIsQ0FBaUIsV0FBakIsS0FDQ0osT0FBTyxDQUFDSSxRQUFSLENBQWlCLGNBQWpCLENBREQsSUFFQ0osT0FBTyxDQUFDSSxRQUFSLENBQWlCLFFBQWpCLENBRkQsSUFHQ0osT0FBTyxDQUFDSSxRQUFSLENBQWlCLFdBQWpCLENBSk0sQ0FBUixJQUtBSCxJQUFJLEtBQUssSUFOSixFQU9MO0FBQ0FLLE1BQUFBLGVBQWUsR0FDYiw2REFERjtBQUVELEtBVk0sTUFVQSxJQUFJQyxRQUFRLElBQUlQLE9BQU8sQ0FBQ0ksUUFBUixDQUFpQixjQUFqQixDQUFaLElBQWdESCxJQUFJLEtBQUssSUFBN0QsRUFBbUU7QUFDeEVLLE1BQUFBLGVBQWUsR0FDYiw2REFERjtBQUVELEtBSE0sTUFHQSxJQUNMQyxRQUFRLElBQ1JQLE9BQU8sQ0FBQ1EsV0FBUixHQUFzQkosUUFBdEIsQ0FBK0IsV0FBL0IsQ0FEQSxJQUVBSCxJQUFJLEtBQUssSUFISixFQUlMO0FBQ0FLLE1BQUFBLGVBQWUsR0FBRyx3Q0FBbEI7QUFDRCxLQU5NLE1BTUEsSUFDTEMsUUFBUSxJQUNSUCxPQUFPLENBQUNJLFFBQVIsQ0FBaUIsUUFBakIsQ0FEQSxJQUVBSixPQUFPLENBQUNRLFdBQVIsR0FBc0JKLFFBQXRCLENBQStCLDJCQUEvQixDQUZBLElBR0FKLE9BQU8sQ0FBQ1EsV0FBUixHQUFzQkosUUFBdEIsQ0FBK0IsTUFBL0IsQ0FIQSxJQUlBSCxJQUFJLEtBQUssSUFMSixFQU1MO0FBQ0FLLE1BQUFBLGVBQWUsR0FBRyx1QkFBbEI7QUFDRCxLQVJNLE1BUUEsSUFBSUMsUUFBUSxJQUFJTixJQUFJLEtBQUssSUFBekIsRUFBK0I7QUFDcENLLE1BQUFBLGVBQWUsR0FBSSwwQkFBeUJOLE9BQVEsR0FBcEQ7QUFDRDtBQUNGOztBQUVELFFBQU1TLGtCQUFrQixHQUFHUCxVQUFVLElBQUksR0FBekM7QUFDQSxTQUFPQyxRQUFRLENBQUNPLE1BQVQsQ0FBZ0I7QUFDckJSLElBQUFBLFVBQVUsRUFBRU8sa0JBRFM7QUFFckJFLElBQUFBLElBQUksRUFBRTtBQUNKWCxNQUFBQSxPQUFPLEVBQUVNLGVBQWUsR0FDbkIsR0FBRUwsSUFBSSxJQUFJLElBQUssTUFBS0ssZUFBZ0IsRUFEakIsR0FFcEIsT0FBT04sT0FBUCxLQUFtQixRQUFuQixHQUNDLEdBQUVDLElBQUksSUFBSSxJQUFLLE1BQUtELE9BQVEsRUFEN0IsR0FFQyxHQUFFQyxJQUFJLElBQUksSUFBSyxxQkFMaEI7QUFNSkEsTUFBQUEsSUFBSSxFQUFFQSxJQUFJLElBQUksSUFOVjtBQU9KQyxNQUFBQSxVQUFVLEVBQUVPO0FBUFI7QUFGZSxHQUFoQixDQUFQO0FBWUQiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gR2VuZXJpYyBlcnJvciByZXNwb25zZSBjb25zdHJ1Y3RvclxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjEgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuLyoqXG4gKiBFcnJvciBjb2RlczpcbiAqIHdhenVoLWFwaS1lbGFzdGljIDIwWFhcbiAqIHdhenVoLWFwaSAgICAgICAgIDMwWFhcbiAqIHdhenVoLWVsYXN0aWMgICAgIDQwWFhcbiAqIHdhenVoLXJlcG9ydGluZyAgIDUwWFhcbiAqIHVua25vd24gICAgICAgICAgIDEwMDBcbiAqL1xuLyoqXG4gKiBSZXR1cm5zIGEgc3VpdGFibGUgZXJyb3IgbWVzc2FnZVxuICogQHBhcmFtIHtTdHJpbmd9IG1lc3NhZ2UgRXJyb3IgbWVzc2FnZVxuICogQHBhcmFtIHtOdW1iZXJ9IGNvZGUgRXJyb3IgY29kZVxuICogQHBhcmFtIHtOdW1iZXJ9IHN0YXR1c0NvZGUgRXJyb3Igc3RhdHVzIGNvZGVcbiAqIEByZXR1cm5zIHtPYmplY3R9IEVycm9yIHJlc3BvbnNlIG9iamVjdFxuICovXG5leHBvcnQgZnVuY3Rpb24gRXJyb3JSZXNwb25zZShcbiAgbWVzc2FnZSA9IG51bGwsXG4gIGNvZGUgPSBudWxsLFxuICBzdGF0dXNDb2RlID0gbnVsbCxcbiAgcmVzcG9uc2Vcbikge1xuICBtZXNzYWdlLmluY2x1ZGVzKCdwYXNzd29yZDogJykgPyBtZXNzYWdlID0gbWVzc2FnZS5zcGxpdCgncGFzc3dvcmQ6ICcpWzBdICsgJyBwYXNzd29yZDogKioqJyA6IGZhbHNlO1xuICBsZXQgZmlsdGVyZWRNZXNzYWdlID0gJyc7XG4gIGlmIChjb2RlKSB7XG4gICAgY29uc3QgaXNTdHJpbmcgPSB0eXBlb2YgbWVzc2FnZSA9PT0gJ3N0cmluZyc7XG4gICAgaWYgKGlzU3RyaW5nICYmIG1lc3NhZ2UgPT09ICdzb2NrZXQgaGFuZyB1cCcgJiYgY29kZSA9PT0gMzAwNSkge1xuICAgICAgZmlsdGVyZWRNZXNzYWdlID0gJ1dyb25nIHByb3RvY29sIGJlaW5nIHVzZWQgdG8gY29ubmVjdCB0byB0aGUgV2F6dWggQVBJJztcbiAgICB9IGVsc2UgaWYgKFxuICAgICAgaXNTdHJpbmcgJiZcbiAgICAgIChtZXNzYWdlLmluY2x1ZGVzKCdFTk9URk9VTkQnKSB8fFxuICAgICAgICBtZXNzYWdlLmluY2x1ZGVzKCdFSE9TVFVOUkVBQ0gnKSB8fFxuICAgICAgICBtZXNzYWdlLmluY2x1ZGVzKCdFSU5WQUwnKSB8fFxuICAgICAgICBtZXNzYWdlLmluY2x1ZGVzKCdFQUlfQUdBSU4nKSkgJiZcbiAgICAgIGNvZGUgPT09IDMwMDVcbiAgICApIHtcbiAgICAgIGZpbHRlcmVkTWVzc2FnZSA9XG4gICAgICAgICdXYXp1aCBBUEkgaXMgbm90IHJlYWNoYWJsZS4gUGxlYXNlIGNoZWNrIHlvdXIgdXJsIGFuZCBwb3J0Lic7XG4gICAgfSBlbHNlIGlmIChpc1N0cmluZyAmJiBtZXNzYWdlLmluY2x1ZGVzKCdFQ09OTlJFRlVTRUQnKSAmJiBjb2RlID09PSAzMDA1KSB7XG4gICAgICBmaWx0ZXJlZE1lc3NhZ2UgPVxuICAgICAgICAnV2F6dWggQVBJIGlzIG5vdCByZWFjaGFibGUuIFBsZWFzZSBjaGVjayB5b3VyIHVybCBhbmQgcG9ydC4nO1xuICAgIH0gZWxzZSBpZiAoXG4gICAgICBpc1N0cmluZyAmJlxuICAgICAgbWVzc2FnZS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKCdub3QgZm91bmQnKSAmJlxuICAgICAgY29kZSA9PT0gMzAwMlxuICAgICkge1xuICAgICAgZmlsdGVyZWRNZXNzYWdlID0gJ0l0IHNlZW1zIHRoZSBzZWxlY3RlZCBBUEkgd2FzIGRlbGV0ZWQuJztcbiAgICB9IGVsc2UgaWYgKFxuICAgICAgaXNTdHJpbmcgJiZcbiAgICAgIG1lc3NhZ2UuaW5jbHVkZXMoJ0VOT0VOVCcpICYmXG4gICAgICBtZXNzYWdlLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoJ25vIHN1Y2ggZmlsZSBvciBkaXJlY3RvcnknKSAmJlxuICAgICAgbWVzc2FnZS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKCdkYXRhJykgJiZcbiAgICAgIGNvZGUgPT09IDUwMjlcbiAgICApIHtcbiAgICAgIGZpbHRlcmVkTWVzc2FnZSA9ICdSZXBvcnRpbmcgd2FzIGFib3J0ZWQnO1xuICAgIH0gZWxzZSBpZiAoaXNTdHJpbmcgJiYgY29kZSA9PT0gNTAyOSkge1xuICAgICAgZmlsdGVyZWRNZXNzYWdlID0gYFJlcG9ydGluZyB3YXMgYWJvcnRlZCAoJHttZXNzYWdlfSlgO1xuICAgIH1cbiAgfVxuXG4gIGNvbnN0IHN0YXR1c0NvZGVSZXNwb25zZSA9IHN0YXR1c0NvZGUgfHwgNTAwO1xuICByZXR1cm4gcmVzcG9uc2UuY3VzdG9tKHtcbiAgICBzdGF0dXNDb2RlOiBzdGF0dXNDb2RlUmVzcG9uc2UsXG4gICAgYm9keToge1xuICAgICAgbWVzc2FnZTogZmlsdGVyZWRNZXNzYWdlXG4gICAgICAgID8gYCR7Y29kZSB8fCAxMDAwfSAtICR7ZmlsdGVyZWRNZXNzYWdlfWBcbiAgICAgICAgOiB0eXBlb2YgbWVzc2FnZSA9PT0gJ3N0cmluZydcbiAgICAgICAgPyBgJHtjb2RlIHx8IDEwMDB9IC0gJHttZXNzYWdlfWBcbiAgICAgICAgOiBgJHtjb2RlIHx8IDEwMDB9IC0gVW5leHBlY3RlZCBlcnJvcmAsXG4gICAgICBjb2RlOiBjb2RlIHx8IDEwMDAsXG4gICAgICBzdGF0dXNDb2RlOiBzdGF0dXNDb2RlUmVzcG9uc2VcbiAgICB9XG4gIH0pXG59XG5cbiJdfQ==