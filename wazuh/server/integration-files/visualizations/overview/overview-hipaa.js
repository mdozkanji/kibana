"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/HIPAA visualizations
 * Copyright (C) 2015-2021 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
var _default = [{
  _id: 'Wazuh-App-Overview-HIPAA-Tag-cloud',
  _source: {
    title: 'Most common alerts',
    visState: '{"title":"Most common alerts","type":"tagcloud","params":{"scale":"linear","orientation":"single","minFontSize":10,"maxFontSize":30,"showLabel":false,"metric":{"type":"vis_dimension","accessor":1,"format":{"id":"string","params":{}}}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"rule.hipaa","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Requirement"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Top-10-requirements',
  _source: {
    title: 'Top 10 requirements',
    visState: '{"title":"Top 10 requirements","type":"pie","params":{"type":"pie","addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":true,"labels":{"show":false,"values":true,"last_level":true,"truncate":100},"dimensions":{"metric":{"accessor":1,"format":{"id":"number"},"params":{},"aggType":"count"},"buckets":[{"accessor":0,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"rule.hipaa","orderBy":"1","order":"desc","size":10,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Top-10-agents',
  _source: {
    title: 'Most active agents',
    visState: '{"title":"Most active agents","type":"pie","params":{"type":"pie","addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":true,"labels":{"show":false,"values":true,"last_level":true,"truncate":100},"dimensions":{"metric":{"accessor":1,"format":{"id":"number"},"params":{},"aggType":"count"},"buckets":[{"accessor":0,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"agent.name","customLabel":"Agent","orderBy":"1","order":"desc","size":10,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Metrics',
  _source: {
    title: 'Stats',
    visState: '{"title":"Stats","type":"metric","params":{"metric":{"percentageMode":false,"useRanges":false,"colorSchema":"Green to Red","metricColorMode":"None","colorsRange":[{"type":"range","from":0,"to":10000}],"labels":{"show":true},"invertColors":false,"style":{"bgFill":"#000","bgColor":false,"labelColor":false,"subText":"","fontSize":20}},"dimensions":{"metrics":[{"type":"vis_dimension","accessor":0,"format":{"id":"number","params":{}}},{"type":"vis_dimension","accessor":1,"format":{"id":"number","params":{}}}]},"addTooltip":true,"addLegend":false,"type":"metric"},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{"customLabel":"Total alerts"}},{"id":"2","enabled":true,"type":"max","schema":"metric","params":{"field":"rule.level","customLabel":"Max rule level detected"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Alerts-summary',
  _source: {
    title: 'Alerts summary',
    visState: '{"title":"Alerts summary","type":"table","params":{"perPage":10,"showPartialRows":false,"showMetricsAtAllLevels":false,"sort":{"columnIndex":3,"direction":"desc"},"showTotal":false,"totalFunc":"sum","dimensions":{"metrics":[{"accessor":3,"format":{"id":"number"},"params":{},"aggType":"count"}],"buckets":[{"accessor":0,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"},{"accessor":1,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"},{"accessor":2,"format":{"id":"terms","params":{"id":"number","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"bucket","params":{"field":"agent.name","orderBy":"1","order":"desc","size":50,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Agent"}},{"id":"3","enabled":true,"type":"terms","schema":"bucket","params":{"field":"rule.hipaa","orderBy":"1","order":"desc","size":20,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Requirement"}},{"id":"4","enabled":true,"type":"terms","schema":"bucket","params":{"field":"rule.level","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Rule level"}}]}',
    uiStateJSON: '{"vis":{"params":{"sort":{"columnIndex":3,"direction":"desc"}}}}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Heatmap',
  _source: {
    title: 'Alerts volume by agent',
    visState: '{"title":"Alerts volume by agent","type":"heatmap","params":{"type":"heatmap","addTooltip":true,"addLegend":true,"enableHover":false,"legendPosition":"right","times":[],"colorsNumber":10,"colorSchema":"Greens","setColorRange":false,"colorsRange":[],"invertColors":false,"percentageMode":false,"valueAxes":[{"show":false,"id":"ValueAxis-1","type":"value","scale":{"type":"linear","defaultYExtents":false},"labels":{"show":false,"rotate":0,"overwriteColor":false,"color":"black"}}],"dimensions":{"x":{"accessor":0,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"},"y":[{"accessor":2,"format":{"id":"number"},"params":{},"aggType":"count"}],"series":[{"accessor":1,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"agent.id","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Agent ID"}},{"id":"3","enabled":true,"type":"terms","schema":"group","params":{"field":"rule.hipaa","orderBy":"1","order":"desc","size":10,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Requirement"}}]}',
    uiStateJSON: '{"vis":{"defaultColors":{"0 - 260":"rgb(247,252,245)","260 - 520":"rgb(233,247,228)","520 - 780":"rgb(211,238,205)","780 - 1,040":"rgb(184,227,177)","1,040 - 1,300":"rgb(152,213,148)","1,300 - 1,560":"rgb(116,196,118)","1,560 - 1,820":"rgb(75,176,98)","1,820 - 2,080":"rgb(47,152,79)","2,080 - 2,340":"rgb(21,127,59)","2,340 - 2,600":"rgb(0,100,40)"},"legendOpen":true}}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Top-10-requirements-over-time-by-agent',
  _source: {
    title: 'Requirements distribution by agent',
    visState: '{"title":"Requirements distribution by agent","type":"histogram","params":{"type":"histogram","grid":{"categoryLines":true,"valueAxis":"ValueAxis-1"},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"filter":true,"truncate":100},"title":{}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left","show":true,"style":{},"scale":{"type":"linear","mode":"normal"},"labels":{"show":true,"rotate":0,"filter":false,"truncate":100},"title":{"text":"Count"}}],"seriesParams":[{"show":"true","type":"histogram","mode":"stacked","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1","drawLinesBetweenPoints":true,"showCircles":true}],"addTooltip":true,"addLegend":true,"legendPosition":"right","times":[],"addTimeMarker":false,"labels":{"show":false},"dimensions":{"x":{"accessor":0,"format":{"id":"date","params":{"pattern":"YYYY-MM-DD HH:mm"}},"params":{"date":true,"interval":"auto","format":"YYYY-MM-DD HH:mm","bounds":{"min":"2019-08-15T12:25:44.851Z","max":"2019-08-22T12:25:44.851Z"}},"aggType":"date_histogram"},"y":[{"accessor":2,"format":{"id":"number"},"params":{},"aggType":"count"}],"series":[{"accessor":1,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"agent.name","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing"}},{"id":"3","enabled":true,"type":"terms","schema":"group","params":{"field":"rule.hipaa","orderBy":"1","order":"desc","size":10,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Top-requirements-over-time',
  _source: {
    title: 'Requirements evolution over time',
    visState: '{"title":"Requirements evolution over time","type":"histogram","params":{"type":"histogram","grid":{"categoryLines":true,"valueAxis":"ValueAxis-1"},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"filter":true,"truncate":100},"title":{}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left","show":true,"style":{},"scale":{"type":"linear","mode":"normal"},"labels":{"show":true,"rotate":0,"filter":false,"truncate":100},"title":{"text":"Count"}}],"seriesParams":[{"show":"true","type":"histogram","mode":"stacked","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1","drawLinesBetweenPoints":true,"showCircles":true}],"addTooltip":true,"addLegend":true,"legendPosition":"right","times":[],"addTimeMarker":false,"labels":{"show":false},"dimensions":{"x":{"accessor":0,"format":{"id":"date","params":{"pattern":"YYYY-MM-DD HH:mm"}},"params":{"date":true,"interval":"auto","format":"YYYY-MM-DD HH:mm","bounds":{"min":"2019-08-15T12:25:29.501Z","max":"2019-08-22T12:25:29.501Z"}},"aggType":"date_histogram"},"y":[{"accessor":2,"format":{"id":"number"},"params":{},"aggType":"count"}],"series":[{"accessor":1,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"date_histogram","schema":"segment","params":{"field":"timestamp","timeRange":{"from":"now-7d","to":"now"},"useNormalizedEsInterval":true,"interval":"auto","drop_partials":false,"min_doc_count":1,"extended_bounds":{}}},{"id":"3","enabled":true,"type":"terms","schema":"group","params":{"field":"rule.hipaa","orderBy":"1","order":"desc","size":10,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"language":"lucene","query":""}}'
    }
  },
  _type: 'visualization'
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LWhpcGFhLnRzIl0sIm5hbWVzIjpbIl9pZCIsIl9zb3VyY2UiLCJ0aXRsZSIsInZpc1N0YXRlIiwidWlTdGF0ZUpTT04iLCJkZXNjcmlwdGlvbiIsInZlcnNpb24iLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiX3R5cGUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTs7Ozs7Ozs7Ozs7ZUFXZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSxvQ0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLG9CQURBO0FBRVBDLElBQUFBLFFBQVEsRUFDTiwrakJBSEs7QUFJUEMsSUFBQUEsV0FBVyxFQUFFLElBSk47QUFLUEMsSUFBQUEsV0FBVyxFQUFFLEVBTE47QUFNUEMsSUFBQUEsT0FBTyxFQUFFLENBTkY7QUFPUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUNkO0FBRm1CO0FBUGhCLEdBRlg7QUFjRUMsRUFBQUEsS0FBSyxFQUFFO0FBZFQsQ0FEYSxFQWlCYjtBQUNFVCxFQUFBQSxHQUFHLEVBQUUsOENBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxxQkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQ04saXhCQUhLO0FBSVBDLElBQUFBLFdBQVcsRUFBRSxJQUpOO0FBS1BDLElBQUFBLFdBQVcsRUFBRSxFQUxOO0FBTVBDLElBQUFBLE9BQU8sRUFBRSxDQU5GO0FBT1BDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFDZDtBQUZtQjtBQVBoQixHQUZYO0FBY0VDLEVBQUFBLEtBQUssRUFBRTtBQWRULENBakJhLEVBaUNiO0FBQ0VULEVBQUFBLEdBQUcsRUFBRSx3Q0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLG9CQURBO0FBRVBDLElBQUFBLFFBQVEsRUFDTixzeUJBSEs7QUFJUEMsSUFBQUEsV0FBVyxFQUFFLElBSk47QUFLUEMsSUFBQUEsV0FBVyxFQUFFLEVBTE47QUFNUEMsSUFBQUEsT0FBTyxFQUFFLENBTkY7QUFPUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUNkO0FBRm1CO0FBUGhCLEdBRlg7QUFjRUMsRUFBQUEsS0FBSyxFQUFFO0FBZFQsQ0FqQ2EsRUFpRGI7QUFDRVQsRUFBQUEsR0FBRyxFQUFFLGtDQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsT0FEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQ04sbXlCQUhLO0FBSVBDLElBQUFBLFdBQVcsRUFBRSxJQUpOO0FBS1BDLElBQUFBLFdBQVcsRUFBRSxFQUxOO0FBTVBDLElBQUFBLE9BQU8sRUFBRSxDQU5GO0FBT1BDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFDZDtBQUZtQjtBQVBoQixHQUZYO0FBY0VDLEVBQUFBLEtBQUssRUFBRTtBQWRULENBakRhLEVBaUViO0FBQ0VULEVBQUFBLEdBQUcsRUFBRSx5Q0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGdCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFDTiw2a0RBSEs7QUFJUEMsSUFBQUEsV0FBVyxFQUNULGtFQUxLO0FBTVBDLElBQUFBLFdBQVcsRUFBRSxFQU5OO0FBT1BDLElBQUFBLE9BQU8sRUFBRSxDQVBGO0FBUVBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFDZDtBQUZtQjtBQVJoQixHQUZYO0FBZUVDLEVBQUFBLEtBQUssRUFBRTtBQWZULENBakVhLEVBa0ZiO0FBQ0VULEVBQUFBLEdBQUcsRUFBRSxrQ0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLHdCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFDTiwyOENBSEs7QUFJUEMsSUFBQUEsV0FBVyxFQUNULG9YQUxLO0FBTVBDLElBQUFBLFdBQVcsRUFBRSxFQU5OO0FBT1BDLElBQUFBLE9BQU8sRUFBRSxDQVBGO0FBUVBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFDZDtBQUZtQjtBQVJoQixHQUZYO0FBZUVDLEVBQUFBLEtBQUssRUFBRTtBQWZULENBbEZhLEVBbUdiO0FBQ0VULEVBQUFBLEdBQUcsRUFBRSxpRUFEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLG9DQURBO0FBRVBDLElBQUFBLFFBQVEsRUFDTix5NERBSEs7QUFJUEMsSUFBQUEsV0FBVyxFQUFFLElBSk47QUFLUEMsSUFBQUEsV0FBVyxFQUFFLEVBTE47QUFNUEMsSUFBQUEsT0FBTyxFQUFFLENBTkY7QUFPUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUNkO0FBRm1CO0FBUGhCLEdBRlg7QUFjRUMsRUFBQUEsS0FBSyxFQUFFO0FBZFQsQ0FuR2EsRUFtSGI7QUFDRVQsRUFBQUEsR0FBRyxFQUFFLHFEQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsa0NBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUNOLDQ1REFISztBQUlQQyxJQUFBQSxXQUFXLEVBQUUsSUFKTjtBQUtQQyxJQUFBQSxXQUFXLEVBQUUsRUFMTjtBQU1QQyxJQUFBQSxPQUFPLEVBQUUsQ0FORjtBQU9QQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQ2Q7QUFGbUI7QUFQaEIsR0FGWDtBQWNFQyxFQUFBQSxLQUFLLEVBQUU7QUFkVCxDQW5IYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgT3ZlcnZpZXcvSElQQUEgdmlzdWFsaXphdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIxIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgZGVmYXVsdCBbXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctSElQQUEtVGFnLWNsb3VkJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ01vc3QgY29tbW9uIGFsZXJ0cycsXG4gICAgICB2aXNTdGF0ZTpcbiAgICAgICAgJ3tcInRpdGxlXCI6XCJNb3N0IGNvbW1vbiBhbGVydHNcIixcInR5cGVcIjpcInRhZ2Nsb3VkXCIsXCJwYXJhbXNcIjp7XCJzY2FsZVwiOlwibGluZWFyXCIsXCJvcmllbnRhdGlvblwiOlwic2luZ2xlXCIsXCJtaW5Gb250U2l6ZVwiOjEwLFwibWF4Rm9udFNpemVcIjozMCxcInNob3dMYWJlbFwiOmZhbHNlLFwibWV0cmljXCI6e1widHlwZVwiOlwidmlzX2RpbWVuc2lvblwiLFwiYWNjZXNzb3JcIjoxLFwiZm9ybWF0XCI6e1wiaWRcIjpcInN0cmluZ1wiLFwicGFyYW1zXCI6e319fX0sXCJhZ2dzXCI6W3tcImlkXCI6XCIxXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcImNvdW50XCIsXCJzY2hlbWFcIjpcIm1ldHJpY1wiLFwicGFyYW1zXCI6e319LHtcImlkXCI6XCIyXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcInNlZ21lbnRcIixcInBhcmFtc1wiOntcImZpZWxkXCI6XCJydWxlLmhpcGFhXCIsXCJvcmRlckJ5XCI6XCIxXCIsXCJvcmRlclwiOlwiZGVzY1wiLFwic2l6ZVwiOjUsXCJvdGhlckJ1Y2tldFwiOmZhbHNlLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRcIjpmYWxzZSxcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wiLFwiY3VzdG9tTGFiZWxcIjpcIlJlcXVpcmVtZW50XCJ9fV19JyxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wibGFuZ3VhZ2VcIjpcImx1Y2VuZVwiLFwicXVlcnlcIjpcIlwifX0nXG4gICAgICB9XG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctSElQQUEtVG9wLTEwLXJlcXVpcmVtZW50cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgMTAgcmVxdWlyZW1lbnRzJyxcbiAgICAgIHZpc1N0YXRlOlxuICAgICAgICAne1widGl0bGVcIjpcIlRvcCAxMCByZXF1aXJlbWVudHNcIixcInR5cGVcIjpcInBpZVwiLFwicGFyYW1zXCI6e1widHlwZVwiOlwicGllXCIsXCJhZGRUb29sdGlwXCI6dHJ1ZSxcImFkZExlZ2VuZFwiOnRydWUsXCJsZWdlbmRQb3NpdGlvblwiOlwicmlnaHRcIixcImlzRG9udXRcIjp0cnVlLFwibGFiZWxzXCI6e1wic2hvd1wiOmZhbHNlLFwidmFsdWVzXCI6dHJ1ZSxcImxhc3RfbGV2ZWxcIjp0cnVlLFwidHJ1bmNhdGVcIjoxMDB9LFwiZGltZW5zaW9uc1wiOntcIm1ldHJpY1wiOntcImFjY2Vzc29yXCI6MSxcImZvcm1hdFwiOntcImlkXCI6XCJudW1iZXJcIn0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcImNvdW50XCJ9LFwiYnVja2V0c1wiOlt7XCJhY2Nlc3NvclwiOjAsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJzdHJpbmdcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifV19fSxcImFnZ3NcIjpbe1wiaWRcIjpcIjFcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwiY291bnRcIixcInNjaGVtYVwiOlwibWV0cmljXCIsXCJwYXJhbXNcIjp7fX0se1wiaWRcIjpcIjJcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwidGVybXNcIixcInNjaGVtYVwiOlwic2VnbWVudFwiLFwicGFyYW1zXCI6e1wiZmllbGRcIjpcInJ1bGUuaGlwYWFcIixcIm9yZGVyQnlcIjpcIjFcIixcIm9yZGVyXCI6XCJkZXNjXCIsXCJzaXplXCI6MTAsXCJvdGhlckJ1Y2tldFwiOmZhbHNlLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRcIjpmYWxzZSxcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wifX1dfScsXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjpcbiAgICAgICAgICAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcImxhbmd1YWdlXCI6XCJsdWNlbmVcIixcInF1ZXJ5XCI6XCJcIn19J1xuICAgICAgfVxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJ1xuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUhJUEFBLVRvcC0xMC1hZ2VudHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTW9zdCBhY3RpdmUgYWdlbnRzJyxcbiAgICAgIHZpc1N0YXRlOlxuICAgICAgICAne1widGl0bGVcIjpcIk1vc3QgYWN0aXZlIGFnZW50c1wiLFwidHlwZVwiOlwicGllXCIsXCJwYXJhbXNcIjp7XCJ0eXBlXCI6XCJwaWVcIixcImFkZFRvb2x0aXBcIjp0cnVlLFwiYWRkTGVnZW5kXCI6dHJ1ZSxcImxlZ2VuZFBvc2l0aW9uXCI6XCJyaWdodFwiLFwiaXNEb251dFwiOnRydWUsXCJsYWJlbHNcIjp7XCJzaG93XCI6ZmFsc2UsXCJ2YWx1ZXNcIjp0cnVlLFwibGFzdF9sZXZlbFwiOnRydWUsXCJ0cnVuY2F0ZVwiOjEwMH0sXCJkaW1lbnNpb25zXCI6e1wibWV0cmljXCI6e1wiYWNjZXNzb3JcIjoxLFwiZm9ybWF0XCI6e1wiaWRcIjpcIm51bWJlclwifSxcInBhcmFtc1wiOnt9LFwiYWdnVHlwZVwiOlwiY291bnRcIn0sXCJidWNrZXRzXCI6W3tcImFjY2Vzc29yXCI6MCxcImZvcm1hdFwiOntcImlkXCI6XCJ0ZXJtc1wiLFwicGFyYW1zXCI6e1wiaWRcIjpcInN0cmluZ1wiLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wifX0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcInRlcm1zXCJ9XX19LFwiYWdnc1wiOlt7XCJpZFwiOlwiMVwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJjb3VudFwiLFwic2NoZW1hXCI6XCJtZXRyaWNcIixcInBhcmFtc1wiOnt9fSx7XCJpZFwiOlwiMlwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJ0ZXJtc1wiLFwic2NoZW1hXCI6XCJzZWdtZW50XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwiYWdlbnQubmFtZVwiLFwiY3VzdG9tTGFiZWxcIjpcIkFnZW50XCIsXCJvcmRlckJ5XCI6XCIxXCIsXCJvcmRlclwiOlwiZGVzY1wiLFwic2l6ZVwiOjEwLFwib3RoZXJCdWNrZXRcIjpmYWxzZSxcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0XCI6ZmFsc2UsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19XX0nLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046XG4gICAgICAgICAgJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJsYW5ndWFnZVwiOlwibHVjZW5lXCIsXCJxdWVyeVwiOlwiXCJ9fSdcbiAgICAgIH1cbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbidcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1ISVBBQS1NZXRyaWNzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1N0YXRzJyxcbiAgICAgIHZpc1N0YXRlOlxuICAgICAgICAne1widGl0bGVcIjpcIlN0YXRzXCIsXCJ0eXBlXCI6XCJtZXRyaWNcIixcInBhcmFtc1wiOntcIm1ldHJpY1wiOntcInBlcmNlbnRhZ2VNb2RlXCI6ZmFsc2UsXCJ1c2VSYW5nZXNcIjpmYWxzZSxcImNvbG9yU2NoZW1hXCI6XCJHcmVlbiB0byBSZWRcIixcIm1ldHJpY0NvbG9yTW9kZVwiOlwiTm9uZVwiLFwiY29sb3JzUmFuZ2VcIjpbe1widHlwZVwiOlwicmFuZ2VcIixcImZyb21cIjowLFwidG9cIjoxMDAwMH1dLFwibGFiZWxzXCI6e1wic2hvd1wiOnRydWV9LFwiaW52ZXJ0Q29sb3JzXCI6ZmFsc2UsXCJzdHlsZVwiOntcImJnRmlsbFwiOlwiIzAwMFwiLFwiYmdDb2xvclwiOmZhbHNlLFwibGFiZWxDb2xvclwiOmZhbHNlLFwic3ViVGV4dFwiOlwiXCIsXCJmb250U2l6ZVwiOjIwfX0sXCJkaW1lbnNpb25zXCI6e1wibWV0cmljc1wiOlt7XCJ0eXBlXCI6XCJ2aXNfZGltZW5zaW9uXCIsXCJhY2Nlc3NvclwiOjAsXCJmb3JtYXRcIjp7XCJpZFwiOlwibnVtYmVyXCIsXCJwYXJhbXNcIjp7fX19LHtcInR5cGVcIjpcInZpc19kaW1lbnNpb25cIixcImFjY2Vzc29yXCI6MSxcImZvcm1hdFwiOntcImlkXCI6XCJudW1iZXJcIixcInBhcmFtc1wiOnt9fX1dfSxcImFkZFRvb2x0aXBcIjp0cnVlLFwiYWRkTGVnZW5kXCI6ZmFsc2UsXCJ0eXBlXCI6XCJtZXRyaWNcIn0sXCJhZ2dzXCI6W3tcImlkXCI6XCIxXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcImNvdW50XCIsXCJzY2hlbWFcIjpcIm1ldHJpY1wiLFwicGFyYW1zXCI6e1wiY3VzdG9tTGFiZWxcIjpcIlRvdGFsIGFsZXJ0c1wifX0se1wiaWRcIjpcIjJcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwibWF4XCIsXCJzY2hlbWFcIjpcIm1ldHJpY1wiLFwicGFyYW1zXCI6e1wiZmllbGRcIjpcInJ1bGUubGV2ZWxcIixcImN1c3RvbUxhYmVsXCI6XCJNYXggcnVsZSBsZXZlbCBkZXRlY3RlZFwifX1dfScsXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjpcbiAgICAgICAgICAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcImxhbmd1YWdlXCI6XCJsdWNlbmVcIixcInF1ZXJ5XCI6XCJcIn19J1xuICAgICAgfVxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJ1xuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUhJUEFBLUFsZXJ0cy1zdW1tYXJ5JyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgIHZpc1N0YXRlOlxuICAgICAgICAne1widGl0bGVcIjpcIkFsZXJ0cyBzdW1tYXJ5XCIsXCJ0eXBlXCI6XCJ0YWJsZVwiLFwicGFyYW1zXCI6e1wicGVyUGFnZVwiOjEwLFwic2hvd1BhcnRpYWxSb3dzXCI6ZmFsc2UsXCJzaG93TWV0cmljc0F0QWxsTGV2ZWxzXCI6ZmFsc2UsXCJzb3J0XCI6e1wiY29sdW1uSW5kZXhcIjozLFwiZGlyZWN0aW9uXCI6XCJkZXNjXCJ9LFwic2hvd1RvdGFsXCI6ZmFsc2UsXCJ0b3RhbEZ1bmNcIjpcInN1bVwiLFwiZGltZW5zaW9uc1wiOntcIm1ldHJpY3NcIjpbe1wiYWNjZXNzb3JcIjozLFwiZm9ybWF0XCI6e1wiaWRcIjpcIm51bWJlclwifSxcInBhcmFtc1wiOnt9LFwiYWdnVHlwZVwiOlwiY291bnRcIn1dLFwiYnVja2V0c1wiOlt7XCJhY2Nlc3NvclwiOjAsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJzdHJpbmdcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifSx7XCJhY2Nlc3NvclwiOjEsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJzdHJpbmdcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifSx7XCJhY2Nlc3NvclwiOjIsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJudW1iZXJcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifV19fSxcImFnZ3NcIjpbe1wiaWRcIjpcIjFcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwiY291bnRcIixcInNjaGVtYVwiOlwibWV0cmljXCIsXCJwYXJhbXNcIjp7fX0se1wiaWRcIjpcIjJcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwidGVybXNcIixcInNjaGVtYVwiOlwiYnVja2V0XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwiYWdlbnQubmFtZVwiLFwib3JkZXJCeVwiOlwiMVwiLFwib3JkZXJcIjpcImRlc2NcIixcInNpemVcIjo1MCxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCIsXCJjdXN0b21MYWJlbFwiOlwiQWdlbnRcIn19LHtcImlkXCI6XCIzXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcImJ1Y2tldFwiLFwicGFyYW1zXCI6e1wiZmllbGRcIjpcInJ1bGUuaGlwYWFcIixcIm9yZGVyQnlcIjpcIjFcIixcIm9yZGVyXCI6XCJkZXNjXCIsXCJzaXplXCI6MjAsXCJvdGhlckJ1Y2tldFwiOmZhbHNlLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRcIjpmYWxzZSxcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wiLFwiY3VzdG9tTGFiZWxcIjpcIlJlcXVpcmVtZW50XCJ9fSx7XCJpZFwiOlwiNFwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJ0ZXJtc1wiLFwic2NoZW1hXCI6XCJidWNrZXRcIixcInBhcmFtc1wiOntcImZpZWxkXCI6XCJydWxlLmxldmVsXCIsXCJvcmRlckJ5XCI6XCIxXCIsXCJvcmRlclwiOlwiZGVzY1wiLFwic2l6ZVwiOjUsXCJvdGhlckJ1Y2tldFwiOmZhbHNlLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRcIjpmYWxzZSxcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wiLFwiY3VzdG9tTGFiZWxcIjpcIlJ1bGUgbGV2ZWxcIn19XX0nLFxuICAgICAgdWlTdGF0ZUpTT046XG4gICAgICAgICd7XCJ2aXNcIjp7XCJwYXJhbXNcIjp7XCJzb3J0XCI6e1wiY29sdW1uSW5kZXhcIjozLFwiZGlyZWN0aW9uXCI6XCJkZXNjXCJ9fX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjpcbiAgICAgICAgICAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcImxhbmd1YWdlXCI6XCJsdWNlbmVcIixcInF1ZXJ5XCI6XCJcIn19J1xuICAgICAgfVxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJ1xuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUhJUEFBLUhlYXRtYXAnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQWxlcnRzIHZvbHVtZSBieSBhZ2VudCcsXG4gICAgICB2aXNTdGF0ZTpcbiAgICAgICAgJ3tcInRpdGxlXCI6XCJBbGVydHMgdm9sdW1lIGJ5IGFnZW50XCIsXCJ0eXBlXCI6XCJoZWF0bWFwXCIsXCJwYXJhbXNcIjp7XCJ0eXBlXCI6XCJoZWF0bWFwXCIsXCJhZGRUb29sdGlwXCI6dHJ1ZSxcImFkZExlZ2VuZFwiOnRydWUsXCJlbmFibGVIb3ZlclwiOmZhbHNlLFwibGVnZW5kUG9zaXRpb25cIjpcInJpZ2h0XCIsXCJ0aW1lc1wiOltdLFwiY29sb3JzTnVtYmVyXCI6MTAsXCJjb2xvclNjaGVtYVwiOlwiR3JlZW5zXCIsXCJzZXRDb2xvclJhbmdlXCI6ZmFsc2UsXCJjb2xvcnNSYW5nZVwiOltdLFwiaW52ZXJ0Q29sb3JzXCI6ZmFsc2UsXCJwZXJjZW50YWdlTW9kZVwiOmZhbHNlLFwidmFsdWVBeGVzXCI6W3tcInNob3dcIjpmYWxzZSxcImlkXCI6XCJWYWx1ZUF4aXMtMVwiLFwidHlwZVwiOlwidmFsdWVcIixcInNjYWxlXCI6e1widHlwZVwiOlwibGluZWFyXCIsXCJkZWZhdWx0WUV4dGVudHNcIjpmYWxzZX0sXCJsYWJlbHNcIjp7XCJzaG93XCI6ZmFsc2UsXCJyb3RhdGVcIjowLFwib3ZlcndyaXRlQ29sb3JcIjpmYWxzZSxcImNvbG9yXCI6XCJibGFja1wifX1dLFwiZGltZW5zaW9uc1wiOntcInhcIjp7XCJhY2Nlc3NvclwiOjAsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJzdHJpbmdcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifSxcInlcIjpbe1wiYWNjZXNzb3JcIjoyLFwiZm9ybWF0XCI6e1wiaWRcIjpcIm51bWJlclwifSxcInBhcmFtc1wiOnt9LFwiYWdnVHlwZVwiOlwiY291bnRcIn1dLFwic2VyaWVzXCI6W3tcImFjY2Vzc29yXCI6MSxcImZvcm1hdFwiOntcImlkXCI6XCJ0ZXJtc1wiLFwicGFyYW1zXCI6e1wiaWRcIjpcInN0cmluZ1wiLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wifX0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcInRlcm1zXCJ9XX19LFwiYWdnc1wiOlt7XCJpZFwiOlwiMVwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJjb3VudFwiLFwic2NoZW1hXCI6XCJtZXRyaWNcIixcInBhcmFtc1wiOnt9fSx7XCJpZFwiOlwiMlwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJ0ZXJtc1wiLFwic2NoZW1hXCI6XCJzZWdtZW50XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwiYWdlbnQuaWRcIixcIm9yZGVyQnlcIjpcIjFcIixcIm9yZGVyXCI6XCJkZXNjXCIsXCJzaXplXCI6NSxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCIsXCJjdXN0b21MYWJlbFwiOlwiQWdlbnQgSURcIn19LHtcImlkXCI6XCIzXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcImdyb3VwXCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwicnVsZS5oaXBhYVwiLFwib3JkZXJCeVwiOlwiMVwiLFwib3JkZXJcIjpcImRlc2NcIixcInNpemVcIjoxMCxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCIsXCJjdXN0b21MYWJlbFwiOlwiUmVxdWlyZW1lbnRcIn19XX0nLFxuICAgICAgdWlTdGF0ZUpTT046XG4gICAgICAgICd7XCJ2aXNcIjp7XCJkZWZhdWx0Q29sb3JzXCI6e1wiMCAtIDI2MFwiOlwicmdiKDI0NywyNTIsMjQ1KVwiLFwiMjYwIC0gNTIwXCI6XCJyZ2IoMjMzLDI0NywyMjgpXCIsXCI1MjAgLSA3ODBcIjpcInJnYigyMTEsMjM4LDIwNSlcIixcIjc4MCAtIDEsMDQwXCI6XCJyZ2IoMTg0LDIyNywxNzcpXCIsXCIxLDA0MCAtIDEsMzAwXCI6XCJyZ2IoMTUyLDIxMywxNDgpXCIsXCIxLDMwMCAtIDEsNTYwXCI6XCJyZ2IoMTE2LDE5NiwxMTgpXCIsXCIxLDU2MCAtIDEsODIwXCI6XCJyZ2IoNzUsMTc2LDk4KVwiLFwiMSw4MjAgLSAyLDA4MFwiOlwicmdiKDQ3LDE1Miw3OSlcIixcIjIsMDgwIC0gMiwzNDBcIjpcInJnYigyMSwxMjcsNTkpXCIsXCIyLDM0MCAtIDIsNjAwXCI6XCJyZ2IoMCwxMDAsNDApXCJ9LFwibGVnZW5kT3BlblwiOnRydWV9fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046XG4gICAgICAgICAgJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJsYW5ndWFnZVwiOlwibHVjZW5lXCIsXCJxdWVyeVwiOlwiXCJ9fSdcbiAgICAgIH1cbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbidcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1ISVBBQS1Ub3AtMTAtcmVxdWlyZW1lbnRzLW92ZXItdGltZS1ieS1hZ2VudCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSZXF1aXJlbWVudHMgZGlzdHJpYnV0aW9uIGJ5IGFnZW50JyxcbiAgICAgIHZpc1N0YXRlOlxuICAgICAgICAne1widGl0bGVcIjpcIlJlcXVpcmVtZW50cyBkaXN0cmlidXRpb24gYnkgYWdlbnRcIixcInR5cGVcIjpcImhpc3RvZ3JhbVwiLFwicGFyYW1zXCI6e1widHlwZVwiOlwiaGlzdG9ncmFtXCIsXCJncmlkXCI6e1wiY2F0ZWdvcnlMaW5lc1wiOnRydWUsXCJ2YWx1ZUF4aXNcIjpcIlZhbHVlQXhpcy0xXCJ9LFwiY2F0ZWdvcnlBeGVzXCI6W3tcImlkXCI6XCJDYXRlZ29yeUF4aXMtMVwiLFwidHlwZVwiOlwiY2F0ZWdvcnlcIixcInBvc2l0aW9uXCI6XCJib3R0b21cIixcInNob3dcIjp0cnVlLFwic3R5bGVcIjp7fSxcInNjYWxlXCI6e1widHlwZVwiOlwibGluZWFyXCJ9LFwibGFiZWxzXCI6e1wic2hvd1wiOnRydWUsXCJmaWx0ZXJcIjp0cnVlLFwidHJ1bmNhdGVcIjoxMDB9LFwidGl0bGVcIjp7fX1dLFwidmFsdWVBeGVzXCI6W3tcImlkXCI6XCJWYWx1ZUF4aXMtMVwiLFwibmFtZVwiOlwiTGVmdEF4aXMtMVwiLFwidHlwZVwiOlwidmFsdWVcIixcInBvc2l0aW9uXCI6XCJsZWZ0XCIsXCJzaG93XCI6dHJ1ZSxcInN0eWxlXCI6e30sXCJzY2FsZVwiOntcInR5cGVcIjpcImxpbmVhclwiLFwibW9kZVwiOlwibm9ybWFsXCJ9LFwibGFiZWxzXCI6e1wic2hvd1wiOnRydWUsXCJyb3RhdGVcIjowLFwiZmlsdGVyXCI6ZmFsc2UsXCJ0cnVuY2F0ZVwiOjEwMH0sXCJ0aXRsZVwiOntcInRleHRcIjpcIkNvdW50XCJ9fV0sXCJzZXJpZXNQYXJhbXNcIjpbe1wic2hvd1wiOlwidHJ1ZVwiLFwidHlwZVwiOlwiaGlzdG9ncmFtXCIsXCJtb2RlXCI6XCJzdGFja2VkXCIsXCJkYXRhXCI6e1wibGFiZWxcIjpcIkNvdW50XCIsXCJpZFwiOlwiMVwifSxcInZhbHVlQXhpc1wiOlwiVmFsdWVBeGlzLTFcIixcImRyYXdMaW5lc0JldHdlZW5Qb2ludHNcIjp0cnVlLFwic2hvd0NpcmNsZXNcIjp0cnVlfV0sXCJhZGRUb29sdGlwXCI6dHJ1ZSxcImFkZExlZ2VuZFwiOnRydWUsXCJsZWdlbmRQb3NpdGlvblwiOlwicmlnaHRcIixcInRpbWVzXCI6W10sXCJhZGRUaW1lTWFya2VyXCI6ZmFsc2UsXCJsYWJlbHNcIjp7XCJzaG93XCI6ZmFsc2V9LFwiZGltZW5zaW9uc1wiOntcInhcIjp7XCJhY2Nlc3NvclwiOjAsXCJmb3JtYXRcIjp7XCJpZFwiOlwiZGF0ZVwiLFwicGFyYW1zXCI6e1wicGF0dGVyblwiOlwiWVlZWS1NTS1ERCBISDptbVwifX0sXCJwYXJhbXNcIjp7XCJkYXRlXCI6dHJ1ZSxcImludGVydmFsXCI6XCJhdXRvXCIsXCJmb3JtYXRcIjpcIllZWVktTU0tREQgSEg6bW1cIixcImJvdW5kc1wiOntcIm1pblwiOlwiMjAxOS0wOC0xNVQxMjoyNTo0NC44NTFaXCIsXCJtYXhcIjpcIjIwMTktMDgtMjJUMTI6MjU6NDQuODUxWlwifX0sXCJhZ2dUeXBlXCI6XCJkYXRlX2hpc3RvZ3JhbVwifSxcInlcIjpbe1wiYWNjZXNzb3JcIjoyLFwiZm9ybWF0XCI6e1wiaWRcIjpcIm51bWJlclwifSxcInBhcmFtc1wiOnt9LFwiYWdnVHlwZVwiOlwiY291bnRcIn1dLFwic2VyaWVzXCI6W3tcImFjY2Vzc29yXCI6MSxcImZvcm1hdFwiOntcImlkXCI6XCJ0ZXJtc1wiLFwicGFyYW1zXCI6e1wiaWRcIjpcInN0cmluZ1wiLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wifX0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcInRlcm1zXCJ9XX19LFwiYWdnc1wiOlt7XCJpZFwiOlwiMVwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJjb3VudFwiLFwic2NoZW1hXCI6XCJtZXRyaWNcIixcInBhcmFtc1wiOnt9fSx7XCJpZFwiOlwiMlwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJ0ZXJtc1wiLFwic2NoZW1hXCI6XCJzZWdtZW50XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwiYWdlbnQubmFtZVwiLFwib3JkZXJCeVwiOlwiMVwiLFwib3JkZXJcIjpcImRlc2NcIixcInNpemVcIjo1LFwib3RoZXJCdWNrZXRcIjpmYWxzZSxcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0XCI6ZmFsc2UsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LHtcImlkXCI6XCIzXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcImdyb3VwXCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwicnVsZS5oaXBhYVwiLFwib3JkZXJCeVwiOlwiMVwiLFwib3JkZXJcIjpcImRlc2NcIixcInNpemVcIjoxMCxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCJ9fV19JyxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wibGFuZ3VhZ2VcIjpcImx1Y2VuZVwiLFwicXVlcnlcIjpcIlwifX0nXG4gICAgICB9XG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctSElQQUEtVG9wLXJlcXVpcmVtZW50cy1vdmVyLXRpbWUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUmVxdWlyZW1lbnRzIGV2b2x1dGlvbiBvdmVyIHRpbWUnLFxuICAgICAgdmlzU3RhdGU6XG4gICAgICAgICd7XCJ0aXRsZVwiOlwiUmVxdWlyZW1lbnRzIGV2b2x1dGlvbiBvdmVyIHRpbWVcIixcInR5cGVcIjpcImhpc3RvZ3JhbVwiLFwicGFyYW1zXCI6e1widHlwZVwiOlwiaGlzdG9ncmFtXCIsXCJncmlkXCI6e1wiY2F0ZWdvcnlMaW5lc1wiOnRydWUsXCJ2YWx1ZUF4aXNcIjpcIlZhbHVlQXhpcy0xXCJ9LFwiY2F0ZWdvcnlBeGVzXCI6W3tcImlkXCI6XCJDYXRlZ29yeUF4aXMtMVwiLFwidHlwZVwiOlwiY2F0ZWdvcnlcIixcInBvc2l0aW9uXCI6XCJib3R0b21cIixcInNob3dcIjp0cnVlLFwic3R5bGVcIjp7fSxcInNjYWxlXCI6e1widHlwZVwiOlwibGluZWFyXCJ9LFwibGFiZWxzXCI6e1wic2hvd1wiOnRydWUsXCJmaWx0ZXJcIjp0cnVlLFwidHJ1bmNhdGVcIjoxMDB9LFwidGl0bGVcIjp7fX1dLFwidmFsdWVBeGVzXCI6W3tcImlkXCI6XCJWYWx1ZUF4aXMtMVwiLFwibmFtZVwiOlwiTGVmdEF4aXMtMVwiLFwidHlwZVwiOlwidmFsdWVcIixcInBvc2l0aW9uXCI6XCJsZWZ0XCIsXCJzaG93XCI6dHJ1ZSxcInN0eWxlXCI6e30sXCJzY2FsZVwiOntcInR5cGVcIjpcImxpbmVhclwiLFwibW9kZVwiOlwibm9ybWFsXCJ9LFwibGFiZWxzXCI6e1wic2hvd1wiOnRydWUsXCJyb3RhdGVcIjowLFwiZmlsdGVyXCI6ZmFsc2UsXCJ0cnVuY2F0ZVwiOjEwMH0sXCJ0aXRsZVwiOntcInRleHRcIjpcIkNvdW50XCJ9fV0sXCJzZXJpZXNQYXJhbXNcIjpbe1wic2hvd1wiOlwidHJ1ZVwiLFwidHlwZVwiOlwiaGlzdG9ncmFtXCIsXCJtb2RlXCI6XCJzdGFja2VkXCIsXCJkYXRhXCI6e1wibGFiZWxcIjpcIkNvdW50XCIsXCJpZFwiOlwiMVwifSxcInZhbHVlQXhpc1wiOlwiVmFsdWVBeGlzLTFcIixcImRyYXdMaW5lc0JldHdlZW5Qb2ludHNcIjp0cnVlLFwic2hvd0NpcmNsZXNcIjp0cnVlfV0sXCJhZGRUb29sdGlwXCI6dHJ1ZSxcImFkZExlZ2VuZFwiOnRydWUsXCJsZWdlbmRQb3NpdGlvblwiOlwicmlnaHRcIixcInRpbWVzXCI6W10sXCJhZGRUaW1lTWFya2VyXCI6ZmFsc2UsXCJsYWJlbHNcIjp7XCJzaG93XCI6ZmFsc2V9LFwiZGltZW5zaW9uc1wiOntcInhcIjp7XCJhY2Nlc3NvclwiOjAsXCJmb3JtYXRcIjp7XCJpZFwiOlwiZGF0ZVwiLFwicGFyYW1zXCI6e1wicGF0dGVyblwiOlwiWVlZWS1NTS1ERCBISDptbVwifX0sXCJwYXJhbXNcIjp7XCJkYXRlXCI6dHJ1ZSxcImludGVydmFsXCI6XCJhdXRvXCIsXCJmb3JtYXRcIjpcIllZWVktTU0tREQgSEg6bW1cIixcImJvdW5kc1wiOntcIm1pblwiOlwiMjAxOS0wOC0xNVQxMjoyNToyOS41MDFaXCIsXCJtYXhcIjpcIjIwMTktMDgtMjJUMTI6MjU6MjkuNTAxWlwifX0sXCJhZ2dUeXBlXCI6XCJkYXRlX2hpc3RvZ3JhbVwifSxcInlcIjpbe1wiYWNjZXNzb3JcIjoyLFwiZm9ybWF0XCI6e1wiaWRcIjpcIm51bWJlclwifSxcInBhcmFtc1wiOnt9LFwiYWdnVHlwZVwiOlwiY291bnRcIn1dLFwic2VyaWVzXCI6W3tcImFjY2Vzc29yXCI6MSxcImZvcm1hdFwiOntcImlkXCI6XCJ0ZXJtc1wiLFwicGFyYW1zXCI6e1wiaWRcIjpcInN0cmluZ1wiLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wifX0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcInRlcm1zXCJ9XX19LFwiYWdnc1wiOlt7XCJpZFwiOlwiMVwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJjb3VudFwiLFwic2NoZW1hXCI6XCJtZXRyaWNcIixcInBhcmFtc1wiOnt9fSx7XCJpZFwiOlwiMlwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJkYXRlX2hpc3RvZ3JhbVwiLFwic2NoZW1hXCI6XCJzZWdtZW50XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwidGltZXN0YW1wXCIsXCJ0aW1lUmFuZ2VcIjp7XCJmcm9tXCI6XCJub3ctN2RcIixcInRvXCI6XCJub3dcIn0sXCJ1c2VOb3JtYWxpemVkRXNJbnRlcnZhbFwiOnRydWUsXCJpbnRlcnZhbFwiOlwiYXV0b1wiLFwiZHJvcF9wYXJ0aWFsc1wiOmZhbHNlLFwibWluX2RvY19jb3VudFwiOjEsXCJleHRlbmRlZF9ib3VuZHNcIjp7fX19LHtcImlkXCI6XCIzXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcImdyb3VwXCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwicnVsZS5oaXBhYVwiLFwib3JkZXJCeVwiOlwiMVwiLFwib3JkZXJcIjpcImRlc2NcIixcInNpemVcIjoxMCxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCJ9fV19JyxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wibGFuZ3VhZ2VcIjpcImx1Y2VuZVwiLFwicXVlcnlcIjpcIlwifX0nXG4gICAgICB9XG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nXG4gIH1cbl07XG4iXX0=