"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/NIST-800-53 visualizations
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
  _id: 'Wazuh-App-Agents-NIST-Stats',
  _source: {
    title: 'Stats',
    visState: '{"title":"Stats","type":"metric","params":{"metric":{"percentageMode":false,"useRanges":false,"colorSchema":"Green to Red","metricColorMode":"None","colorsRange":[{"type":"range","from":0,"to":10000}],"labels":{"show":true},"invertColors":false,"style":{"bgFill":"#000","bgColor":false,"labelColor":false,"subText":"","fontSize":20}},"dimensions":{"metrics":[{"type":"vis_dimension","accessor":0,"format":{"id":"number","params":{}}},{"type":"vis_dimension","accessor":1,"format":{"id":"number","params":{}}}]},"addTooltip":true,"addLegend":false,"type":"metric"},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{"customLabel":"Total alerts"}},{"id":"3","enabled":true,"type":"max","schema":"metric","params":{"field":"rule.level","customLabel":"Max rule level"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-NIST-top-10-requirements',
  _source: {
    title: 'Top 10 requirements',
    visState: '{"title":"Top 10 requirements","type":"pie","params":{"type":"pie","addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":true,"labels":{"show":false,"values":true,"last_level":true,"truncate":100},"dimensions":{"metric":{"accessor":0,"format":{"id":"number"},"params":{},"aggType":"count"}}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"rule.nist_800_53","orderBy":"1","order":"desc","size":10,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Requirement"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-NIST-Requirement-by-level',
  _source: {
    title: 'Requirements distributed by level',
    visState: '{"title":"Requirements distributed by level","type":"histogram","params":{"type":"histogram","grid":{"categoryLines":false},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"left","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"rotate":0,"filter":false,"truncate":200},"title":{}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"bottom","show":true,"style":{},"scale":{"type":"linear","mode":"normal"},"labels":{"show":true,"rotate":75,"filter":true,"truncate":100},"title":{"text":"Count"}}],"seriesParams":[{"show":true,"type":"histogram","mode":"stacked","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1","drawLinesBetweenPoints":true,"showCircles":true}],"addTooltip":true,"addLegend":true,"legendPosition":"right","times":[],"addTimeMarker":false,"dimensions":{"x":{"accessor":0,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"},"y":[{"accessor":2,"format":{"id":"number"},"params":{},"aggType":"count"}],"series":[{"accessor":1,"format":{"id":"terms","params":{"id":"number","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]},"labels":{"show":false}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"rule.nist_800_53","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Requirement"}},{"id":"3","enabled":true,"type":"terms","schema":"group","params":{"field":"rule.level","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Level"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-NIST-Rule-level-distribution',
  _source: {
    title: 'Rule level distribution',
    visState: '{"title":"Rule level distribution","type":"pie","params":{"type":"pie","addTooltip":true,"addLegend":false,"legendPosition":"right","isDonut":true,"labels":{"show":true,"values":true,"last_level":true,"truncate":100}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"rule.level","size":15,"order":"desc","orderBy":"1","otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing"}}]}',
    uiStateJSON: '{"vis":{"legendOpen":false}}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-NIST-Requirements-stacked-overtime',
  _source: {
    title: 'Requirements over time',
    visState: '{"title":"Requirements over time","type":"histogram","params":{"type":"histogram","grid":{"categoryLines":true,"valueAxis":"ValueAxis-1"},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"filter":true,"truncate":100},"title":{}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left","show":true,"style":{},"scale":{"type":"linear","mode":"normal"},"labels":{"show":true,"rotate":0,"filter":false,"truncate":100},"title":{"text":"Count"}}],"seriesParams":[{"show":"true","type":"histogram","mode":"stacked","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1","drawLinesBetweenPoints":true,"showCircles":true}],"addTooltip":true,"addLegend":true,"legendPosition":"right","times":[],"addTimeMarker":false,"labels":{"show":false},"dimensions":{"x":{"accessor":0,"format":{"id":"date","params":{"pattern":"YYYY-MM-DD HH:mm"}},"params":{"date":true,"interval":"PT1H","format":"YYYY-MM-DD HH:mm","bounds":{"min":"2019-08-19T09:46:35.795Z","max":"2019-08-23T09:46:35.795Z"}},"aggType":"date_histogram"},"y":[{"accessor":2,"format":{"id":"number"},"params":{},"aggType":"count"}],"series":[{"accessor":1,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"date_histogram","schema":"segment","params":{"field":"timestamp","timeRange":{"from":"now-4d","to":"now"},"useNormalizedEsInterval":true,"interval":"auto","drop_partials":false,"min_doc_count":1,"extended_bounds":{},"customLabel":"Timestamp"}},{"id":"3","enabled":true,"type":"terms","schema":"group","params":{"field":"rule.hipaa","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Requirement"}}]}',
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-NIST-Last-alerts',
  _type: 'visualization',
  _source: {
    title: 'Alerts summary',
    visState: '{"title":"Alerts summary","type":"table","params":{"perPage":10,"showPartialRows":false,"showMetricsAtAllLevels":false,"sort":{"columnIndex":3,"direction":"desc"},"showTotal":false,"totalFunc":"sum","dimensions":{"metrics":[{"accessor":3,"format":{"id":"number"},"params":{},"aggType":"count"}],"buckets":[{"accessor":0,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"},{"accessor":1,"format":{"id":"terms","params":{"id":"number","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"},{"accessor":2,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}]}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"3","enabled":true,"type":"terms","schema":"bucket","params":{"field":"rule.nist_800_53","orderBy":"1","order":"desc","size":20,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Requirement"}},{"id":"4","enabled":true,"type":"terms","schema":"bucket","params":{"field":"rule.level","orderBy":"1","order":"desc","size":5,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Rule level"}},{"id":"5","enabled":true,"type":"terms","schema":"bucket","params":{"field":"rule.description","orderBy":"1","order":"desc","size":200,"otherBucket":false,"otherBucketLabel":"Other","missingBucket":false,"missingBucketLabel":"Missing","customLabel":"Description"}}]}',
    uiStateJSON: '{"vis":{"params":{"sort":{"columnIndex":3,"direction":"desc"}}}}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  }
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1uaXN0LnRzIl0sIm5hbWVzIjpbIl9pZCIsIl9zb3VyY2UiLCJ0aXRsZSIsInZpc1N0YXRlIiwidWlTdGF0ZUpTT04iLCJkZXNjcmlwdGlvbiIsInZlcnNpb24iLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiX3R5cGUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTs7Ozs7Ozs7Ozs7ZUFXZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSw2QkFEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLE9BREE7QUFFUEMsSUFBQUEsUUFBUSxFQUNOLDB4QkFISztBQUlQQyxJQUFBQSxXQUFXLEVBQUUsSUFKTjtBQUtQQyxJQUFBQSxXQUFXLEVBQUUsRUFMTjtBQU1QQyxJQUFBQSxPQUFPLEVBQUUsQ0FORjtBQU9QQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQ2Q7QUFGbUI7QUFQaEIsR0FGWDtBQWNFQyxFQUFBQSxLQUFLLEVBQUU7QUFkVCxDQURhLEVBaUJiO0FBQ0VULEVBQUFBLEdBQUcsRUFBRSwyQ0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLHFCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFDTiwrb0JBSEs7QUFJUEMsSUFBQUEsV0FBVyxFQUFFLElBSk47QUFLUEMsSUFBQUEsV0FBVyxFQUFFLEVBTE47QUFNUEMsSUFBQUEsT0FBTyxFQUFFLENBTkY7QUFPUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUNkO0FBRm1CO0FBUGhCLEdBRlg7QUFjRUMsRUFBQUEsS0FBSyxFQUFFO0FBZFQsQ0FqQmEsRUFpQ2I7QUFDRVQsRUFBQUEsR0FBRyxFQUFFLDRDQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsbUNBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUNOLDYwREFISztBQUlQQyxJQUFBQSxXQUFXLEVBQUUsSUFKTjtBQUtQQyxJQUFBQSxXQUFXLEVBQUUsRUFMTjtBQU1QQyxJQUFBQSxPQUFPLEVBQUUsQ0FORjtBQU9QQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQ2Q7QUFGbUI7QUFQaEIsR0FGWDtBQWNFQyxFQUFBQSxLQUFLLEVBQUU7QUFkVCxDQWpDYSxFQWlEYjtBQUNFVCxFQUFBQSxHQUFHLEVBQUUsK0NBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSx5QkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQ04sbWhCQUhLO0FBSVBDLElBQUFBLFdBQVcsRUFBRSw4QkFKTjtBQUtQQyxJQUFBQSxXQUFXLEVBQUUsRUFMTjtBQU1QQyxJQUFBQSxPQUFPLEVBQUUsQ0FORjtBQU9QQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQ2Q7QUFGbUI7QUFQaEIsR0FGWDtBQWNFQyxFQUFBQSxLQUFLLEVBQUU7QUFkVCxDQWpEYSxFQWlFYjtBQUNFVCxFQUFBQSxHQUFHLEVBQUUscURBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSx3QkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQ04sdThEQUhLO0FBSVBDLElBQUFBLFdBQVcsRUFBRSxJQUpOO0FBS1BDLElBQUFBLFdBQVcsRUFBRSxFQUxOO0FBTVBDLElBQUFBLE9BQU8sRUFBRSxDQU5GO0FBT1BDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFDZDtBQUZtQjtBQVBoQixHQUZYO0FBY0VDLEVBQUFBLEtBQUssRUFBRTtBQWRULENBakVhLEVBaUZiO0FBQ0VULEVBQUFBLEdBQUcsRUFBRSxtQ0FEUDtBQUVFUyxFQUFBQSxLQUFLLEVBQUUsZUFGVDtBQUdFUixFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGdCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFDTixnbURBSEs7QUFJUEMsSUFBQUEsV0FBVyxFQUNULGtFQUxLO0FBTVBDLElBQUFBLFdBQVcsRUFBRSxFQU5OO0FBT1BDLElBQUFBLE9BQU8sRUFBRSxDQVBGO0FBUVBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFDZDtBQUZtQjtBQVJoQjtBQUhYLENBakZhLEMiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIGZvciBBZ2VudHMvTklTVC04MDAtNTMgdmlzdWFsaXphdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIxIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgZGVmYXVsdCBbXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU5JU1QtU3RhdHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnU3RhdHMnLFxuICAgICAgdmlzU3RhdGU6XG4gICAgICAgICd7XCJ0aXRsZVwiOlwiU3RhdHNcIixcInR5cGVcIjpcIm1ldHJpY1wiLFwicGFyYW1zXCI6e1wibWV0cmljXCI6e1wicGVyY2VudGFnZU1vZGVcIjpmYWxzZSxcInVzZVJhbmdlc1wiOmZhbHNlLFwiY29sb3JTY2hlbWFcIjpcIkdyZWVuIHRvIFJlZFwiLFwibWV0cmljQ29sb3JNb2RlXCI6XCJOb25lXCIsXCJjb2xvcnNSYW5nZVwiOlt7XCJ0eXBlXCI6XCJyYW5nZVwiLFwiZnJvbVwiOjAsXCJ0b1wiOjEwMDAwfV0sXCJsYWJlbHNcIjp7XCJzaG93XCI6dHJ1ZX0sXCJpbnZlcnRDb2xvcnNcIjpmYWxzZSxcInN0eWxlXCI6e1wiYmdGaWxsXCI6XCIjMDAwXCIsXCJiZ0NvbG9yXCI6ZmFsc2UsXCJsYWJlbENvbG9yXCI6ZmFsc2UsXCJzdWJUZXh0XCI6XCJcIixcImZvbnRTaXplXCI6MjB9fSxcImRpbWVuc2lvbnNcIjp7XCJtZXRyaWNzXCI6W3tcInR5cGVcIjpcInZpc19kaW1lbnNpb25cIixcImFjY2Vzc29yXCI6MCxcImZvcm1hdFwiOntcImlkXCI6XCJudW1iZXJcIixcInBhcmFtc1wiOnt9fX0se1widHlwZVwiOlwidmlzX2RpbWVuc2lvblwiLFwiYWNjZXNzb3JcIjoxLFwiZm9ybWF0XCI6e1wiaWRcIjpcIm51bWJlclwiLFwicGFyYW1zXCI6e319fV19LFwiYWRkVG9vbHRpcFwiOnRydWUsXCJhZGRMZWdlbmRcIjpmYWxzZSxcInR5cGVcIjpcIm1ldHJpY1wifSxcImFnZ3NcIjpbe1wiaWRcIjpcIjFcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwiY291bnRcIixcInNjaGVtYVwiOlwibWV0cmljXCIsXCJwYXJhbXNcIjp7XCJjdXN0b21MYWJlbFwiOlwiVG90YWwgYWxlcnRzXCJ9fSx7XCJpZFwiOlwiM1wiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJtYXhcIixcInNjaGVtYVwiOlwibWV0cmljXCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwicnVsZS5sZXZlbFwiLFwiY3VzdG9tTGFiZWxcIjpcIk1heCBydWxlIGxldmVsXCJ9fV19JyxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wicXVlcnlcIjpcIlwiLFwibGFuZ3VhZ2VcIjpcImx1Y2VuZVwifX0nXG4gICAgICB9XG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU5JU1QtdG9wLTEwLXJlcXVpcmVtZW50cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgMTAgcmVxdWlyZW1lbnRzJyxcbiAgICAgIHZpc1N0YXRlOlxuICAgICAgICAne1widGl0bGVcIjpcIlRvcCAxMCByZXF1aXJlbWVudHNcIixcInR5cGVcIjpcInBpZVwiLFwicGFyYW1zXCI6e1widHlwZVwiOlwicGllXCIsXCJhZGRUb29sdGlwXCI6dHJ1ZSxcImFkZExlZ2VuZFwiOnRydWUsXCJsZWdlbmRQb3NpdGlvblwiOlwicmlnaHRcIixcImlzRG9udXRcIjp0cnVlLFwibGFiZWxzXCI6e1wic2hvd1wiOmZhbHNlLFwidmFsdWVzXCI6dHJ1ZSxcImxhc3RfbGV2ZWxcIjp0cnVlLFwidHJ1bmNhdGVcIjoxMDB9LFwiZGltZW5zaW9uc1wiOntcIm1ldHJpY1wiOntcImFjY2Vzc29yXCI6MCxcImZvcm1hdFwiOntcImlkXCI6XCJudW1iZXJcIn0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcImNvdW50XCJ9fX0sXCJhZ2dzXCI6W3tcImlkXCI6XCIxXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcImNvdW50XCIsXCJzY2hlbWFcIjpcIm1ldHJpY1wiLFwicGFyYW1zXCI6e319LHtcImlkXCI6XCIyXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcInNlZ21lbnRcIixcInBhcmFtc1wiOntcImZpZWxkXCI6XCJydWxlLm5pc3RfODAwXzUzXCIsXCJvcmRlckJ5XCI6XCIxXCIsXCJvcmRlclwiOlwiZGVzY1wiLFwic2l6ZVwiOjEwLFwib3RoZXJCdWNrZXRcIjpmYWxzZSxcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0XCI6ZmFsc2UsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIixcImN1c3RvbUxhYmVsXCI6XCJSZXF1aXJlbWVudFwifX1dfScsXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjpcbiAgICAgICAgICAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcInF1ZXJ5XCI6XCJcIixcImxhbmd1YWdlXCI6XCJsdWNlbmVcIn19J1xuICAgICAgfVxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJ1xuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1OSVNULVJlcXVpcmVtZW50LWJ5LWxldmVsJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1JlcXVpcmVtZW50cyBkaXN0cmlidXRlZCBieSBsZXZlbCcsXG4gICAgICB2aXNTdGF0ZTpcbiAgICAgICAgJ3tcInRpdGxlXCI6XCJSZXF1aXJlbWVudHMgZGlzdHJpYnV0ZWQgYnkgbGV2ZWxcIixcInR5cGVcIjpcImhpc3RvZ3JhbVwiLFwicGFyYW1zXCI6e1widHlwZVwiOlwiaGlzdG9ncmFtXCIsXCJncmlkXCI6e1wiY2F0ZWdvcnlMaW5lc1wiOmZhbHNlfSxcImNhdGVnb3J5QXhlc1wiOlt7XCJpZFwiOlwiQ2F0ZWdvcnlBeGlzLTFcIixcInR5cGVcIjpcImNhdGVnb3J5XCIsXCJwb3NpdGlvblwiOlwibGVmdFwiLFwic2hvd1wiOnRydWUsXCJzdHlsZVwiOnt9LFwic2NhbGVcIjp7XCJ0eXBlXCI6XCJsaW5lYXJcIn0sXCJsYWJlbHNcIjp7XCJzaG93XCI6dHJ1ZSxcInJvdGF0ZVwiOjAsXCJmaWx0ZXJcIjpmYWxzZSxcInRydW5jYXRlXCI6MjAwfSxcInRpdGxlXCI6e319XSxcInZhbHVlQXhlc1wiOlt7XCJpZFwiOlwiVmFsdWVBeGlzLTFcIixcIm5hbWVcIjpcIkxlZnRBeGlzLTFcIixcInR5cGVcIjpcInZhbHVlXCIsXCJwb3NpdGlvblwiOlwiYm90dG9tXCIsXCJzaG93XCI6dHJ1ZSxcInN0eWxlXCI6e30sXCJzY2FsZVwiOntcInR5cGVcIjpcImxpbmVhclwiLFwibW9kZVwiOlwibm9ybWFsXCJ9LFwibGFiZWxzXCI6e1wic2hvd1wiOnRydWUsXCJyb3RhdGVcIjo3NSxcImZpbHRlclwiOnRydWUsXCJ0cnVuY2F0ZVwiOjEwMH0sXCJ0aXRsZVwiOntcInRleHRcIjpcIkNvdW50XCJ9fV0sXCJzZXJpZXNQYXJhbXNcIjpbe1wic2hvd1wiOnRydWUsXCJ0eXBlXCI6XCJoaXN0b2dyYW1cIixcIm1vZGVcIjpcInN0YWNrZWRcIixcImRhdGFcIjp7XCJsYWJlbFwiOlwiQ291bnRcIixcImlkXCI6XCIxXCJ9LFwidmFsdWVBeGlzXCI6XCJWYWx1ZUF4aXMtMVwiLFwiZHJhd0xpbmVzQmV0d2VlblBvaW50c1wiOnRydWUsXCJzaG93Q2lyY2xlc1wiOnRydWV9XSxcImFkZFRvb2x0aXBcIjp0cnVlLFwiYWRkTGVnZW5kXCI6dHJ1ZSxcImxlZ2VuZFBvc2l0aW9uXCI6XCJyaWdodFwiLFwidGltZXNcIjpbXSxcImFkZFRpbWVNYXJrZXJcIjpmYWxzZSxcImRpbWVuc2lvbnNcIjp7XCJ4XCI6e1wiYWNjZXNzb3JcIjowLFwiZm9ybWF0XCI6e1wiaWRcIjpcInRlcm1zXCIsXCJwYXJhbXNcIjp7XCJpZFwiOlwic3RyaW5nXCIsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCJ9fSxcInBhcmFtc1wiOnt9LFwiYWdnVHlwZVwiOlwidGVybXNcIn0sXCJ5XCI6W3tcImFjY2Vzc29yXCI6MixcImZvcm1hdFwiOntcImlkXCI6XCJudW1iZXJcIn0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcImNvdW50XCJ9XSxcInNlcmllc1wiOlt7XCJhY2Nlc3NvclwiOjEsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJudW1iZXJcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifV19LFwibGFiZWxzXCI6e1wic2hvd1wiOmZhbHNlfX0sXCJhZ2dzXCI6W3tcImlkXCI6XCIxXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcImNvdW50XCIsXCJzY2hlbWFcIjpcIm1ldHJpY1wiLFwicGFyYW1zXCI6e319LHtcImlkXCI6XCIyXCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcInNlZ21lbnRcIixcInBhcmFtc1wiOntcImZpZWxkXCI6XCJydWxlLm5pc3RfODAwXzUzXCIsXCJvcmRlckJ5XCI6XCIxXCIsXCJvcmRlclwiOlwiZGVzY1wiLFwic2l6ZVwiOjUsXCJvdGhlckJ1Y2tldFwiOmZhbHNlLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRcIjpmYWxzZSxcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wiLFwiY3VzdG9tTGFiZWxcIjpcIlJlcXVpcmVtZW50XCJ9fSx7XCJpZFwiOlwiM1wiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJ0ZXJtc1wiLFwic2NoZW1hXCI6XCJncm91cFwiLFwicGFyYW1zXCI6e1wiZmllbGRcIjpcInJ1bGUubGV2ZWxcIixcIm9yZGVyQnlcIjpcIjFcIixcIm9yZGVyXCI6XCJkZXNjXCIsXCJzaXplXCI6NSxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCIsXCJjdXN0b21MYWJlbFwiOlwiTGV2ZWxcIn19XX0nLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046XG4gICAgICAgICAgJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJxdWVyeVwiOlwiXCIsXCJsYW5ndWFnZVwiOlwibHVjZW5lXCJ9fSdcbiAgICAgIH1cbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbidcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTklTVC1SdWxlLWxldmVsLWRpc3RyaWJ1dGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSdWxlIGxldmVsIGRpc3RyaWJ1dGlvbicsXG4gICAgICB2aXNTdGF0ZTpcbiAgICAgICAgJ3tcInRpdGxlXCI6XCJSdWxlIGxldmVsIGRpc3RyaWJ1dGlvblwiLFwidHlwZVwiOlwicGllXCIsXCJwYXJhbXNcIjp7XCJ0eXBlXCI6XCJwaWVcIixcImFkZFRvb2x0aXBcIjp0cnVlLFwiYWRkTGVnZW5kXCI6ZmFsc2UsXCJsZWdlbmRQb3NpdGlvblwiOlwicmlnaHRcIixcImlzRG9udXRcIjp0cnVlLFwibGFiZWxzXCI6e1wic2hvd1wiOnRydWUsXCJ2YWx1ZXNcIjp0cnVlLFwibGFzdF9sZXZlbFwiOnRydWUsXCJ0cnVuY2F0ZVwiOjEwMH19LFwiYWdnc1wiOlt7XCJpZFwiOlwiMVwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJjb3VudFwiLFwic2NoZW1hXCI6XCJtZXRyaWNcIixcInBhcmFtc1wiOnt9fSx7XCJpZFwiOlwiMlwiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJ0ZXJtc1wiLFwic2NoZW1hXCI6XCJzZWdtZW50XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwicnVsZS5sZXZlbFwiLFwic2l6ZVwiOjE1LFwib3JkZXJcIjpcImRlc2NcIixcIm9yZGVyQnlcIjpcIjFcIixcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCJ9fV19JyxcbiAgICAgIHVpU3RhdGVKU09OOiAne1widmlzXCI6e1wibGVnZW5kT3BlblwiOmZhbHNlfX0nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wicXVlcnlcIjpcIlwiLFwibGFuZ3VhZ2VcIjpcImx1Y2VuZVwifX0nXG4gICAgICB9XG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU5JU1QtUmVxdWlyZW1lbnRzLXN0YWNrZWQtb3ZlcnRpbWUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUmVxdWlyZW1lbnRzIG92ZXIgdGltZScsXG4gICAgICB2aXNTdGF0ZTpcbiAgICAgICAgJ3tcInRpdGxlXCI6XCJSZXF1aXJlbWVudHMgb3ZlciB0aW1lXCIsXCJ0eXBlXCI6XCJoaXN0b2dyYW1cIixcInBhcmFtc1wiOntcInR5cGVcIjpcImhpc3RvZ3JhbVwiLFwiZ3JpZFwiOntcImNhdGVnb3J5TGluZXNcIjp0cnVlLFwidmFsdWVBeGlzXCI6XCJWYWx1ZUF4aXMtMVwifSxcImNhdGVnb3J5QXhlc1wiOlt7XCJpZFwiOlwiQ2F0ZWdvcnlBeGlzLTFcIixcInR5cGVcIjpcImNhdGVnb3J5XCIsXCJwb3NpdGlvblwiOlwiYm90dG9tXCIsXCJzaG93XCI6dHJ1ZSxcInN0eWxlXCI6e30sXCJzY2FsZVwiOntcInR5cGVcIjpcImxpbmVhclwifSxcImxhYmVsc1wiOntcInNob3dcIjp0cnVlLFwiZmlsdGVyXCI6dHJ1ZSxcInRydW5jYXRlXCI6MTAwfSxcInRpdGxlXCI6e319XSxcInZhbHVlQXhlc1wiOlt7XCJpZFwiOlwiVmFsdWVBeGlzLTFcIixcIm5hbWVcIjpcIkxlZnRBeGlzLTFcIixcInR5cGVcIjpcInZhbHVlXCIsXCJwb3NpdGlvblwiOlwibGVmdFwiLFwic2hvd1wiOnRydWUsXCJzdHlsZVwiOnt9LFwic2NhbGVcIjp7XCJ0eXBlXCI6XCJsaW5lYXJcIixcIm1vZGVcIjpcIm5vcm1hbFwifSxcImxhYmVsc1wiOntcInNob3dcIjp0cnVlLFwicm90YXRlXCI6MCxcImZpbHRlclwiOmZhbHNlLFwidHJ1bmNhdGVcIjoxMDB9LFwidGl0bGVcIjp7XCJ0ZXh0XCI6XCJDb3VudFwifX1dLFwic2VyaWVzUGFyYW1zXCI6W3tcInNob3dcIjpcInRydWVcIixcInR5cGVcIjpcImhpc3RvZ3JhbVwiLFwibW9kZVwiOlwic3RhY2tlZFwiLFwiZGF0YVwiOntcImxhYmVsXCI6XCJDb3VudFwiLFwiaWRcIjpcIjFcIn0sXCJ2YWx1ZUF4aXNcIjpcIlZhbHVlQXhpcy0xXCIsXCJkcmF3TGluZXNCZXR3ZWVuUG9pbnRzXCI6dHJ1ZSxcInNob3dDaXJjbGVzXCI6dHJ1ZX1dLFwiYWRkVG9vbHRpcFwiOnRydWUsXCJhZGRMZWdlbmRcIjp0cnVlLFwibGVnZW5kUG9zaXRpb25cIjpcInJpZ2h0XCIsXCJ0aW1lc1wiOltdLFwiYWRkVGltZU1hcmtlclwiOmZhbHNlLFwibGFiZWxzXCI6e1wic2hvd1wiOmZhbHNlfSxcImRpbWVuc2lvbnNcIjp7XCJ4XCI6e1wiYWNjZXNzb3JcIjowLFwiZm9ybWF0XCI6e1wiaWRcIjpcImRhdGVcIixcInBhcmFtc1wiOntcInBhdHRlcm5cIjpcIllZWVktTU0tREQgSEg6bW1cIn19LFwicGFyYW1zXCI6e1wiZGF0ZVwiOnRydWUsXCJpbnRlcnZhbFwiOlwiUFQxSFwiLFwiZm9ybWF0XCI6XCJZWVlZLU1NLUREIEhIOm1tXCIsXCJib3VuZHNcIjp7XCJtaW5cIjpcIjIwMTktMDgtMTlUMDk6NDY6MzUuNzk1WlwiLFwibWF4XCI6XCIyMDE5LTA4LTIzVDA5OjQ2OjM1Ljc5NVpcIn19LFwiYWdnVHlwZVwiOlwiZGF0ZV9oaXN0b2dyYW1cIn0sXCJ5XCI6W3tcImFjY2Vzc29yXCI6MixcImZvcm1hdFwiOntcImlkXCI6XCJudW1iZXJcIn0sXCJwYXJhbXNcIjp7fSxcImFnZ1R5cGVcIjpcImNvdW50XCJ9XSxcInNlcmllc1wiOlt7XCJhY2Nlc3NvclwiOjEsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJzdHJpbmdcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifV19fSxcImFnZ3NcIjpbe1wiaWRcIjpcIjFcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwiY291bnRcIixcInNjaGVtYVwiOlwibWV0cmljXCIsXCJwYXJhbXNcIjp7fX0se1wiaWRcIjpcIjJcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwiZGF0ZV9oaXN0b2dyYW1cIixcInNjaGVtYVwiOlwic2VnbWVudFwiLFwicGFyYW1zXCI6e1wiZmllbGRcIjpcInRpbWVzdGFtcFwiLFwidGltZVJhbmdlXCI6e1wiZnJvbVwiOlwibm93LTRkXCIsXCJ0b1wiOlwibm93XCJ9LFwidXNlTm9ybWFsaXplZEVzSW50ZXJ2YWxcIjp0cnVlLFwiaW50ZXJ2YWxcIjpcImF1dG9cIixcImRyb3BfcGFydGlhbHNcIjpmYWxzZSxcIm1pbl9kb2NfY291bnRcIjoxLFwiZXh0ZW5kZWRfYm91bmRzXCI6e30sXCJjdXN0b21MYWJlbFwiOlwiVGltZXN0YW1wXCJ9fSx7XCJpZFwiOlwiM1wiLFwiZW5hYmxlZFwiOnRydWUsXCJ0eXBlXCI6XCJ0ZXJtc1wiLFwic2NoZW1hXCI6XCJncm91cFwiLFwicGFyYW1zXCI6e1wiZmllbGRcIjpcInJ1bGUuaGlwYWFcIixcIm9yZGVyQnlcIjpcIjFcIixcIm9yZGVyXCI6XCJkZXNjXCIsXCJzaXplXCI6NSxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCIsXCJjdXN0b21MYWJlbFwiOlwiUmVxdWlyZW1lbnRcIn19XX0nLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046XG4gICAgICAgICAgJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJxdWVyeVwiOlwiXCIsXCJsYW5ndWFnZVwiOlwibHVjZW5lXCJ9fSdcbiAgICAgIH1cbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbidcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTklTVC1MYXN0LWFsZXJ0cycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgIHZpc1N0YXRlOlxuICAgICAgICAne1widGl0bGVcIjpcIkFsZXJ0cyBzdW1tYXJ5XCIsXCJ0eXBlXCI6XCJ0YWJsZVwiLFwicGFyYW1zXCI6e1wicGVyUGFnZVwiOjEwLFwic2hvd1BhcnRpYWxSb3dzXCI6ZmFsc2UsXCJzaG93TWV0cmljc0F0QWxsTGV2ZWxzXCI6ZmFsc2UsXCJzb3J0XCI6e1wiY29sdW1uSW5kZXhcIjozLFwiZGlyZWN0aW9uXCI6XCJkZXNjXCJ9LFwic2hvd1RvdGFsXCI6ZmFsc2UsXCJ0b3RhbEZ1bmNcIjpcInN1bVwiLFwiZGltZW5zaW9uc1wiOntcIm1ldHJpY3NcIjpbe1wiYWNjZXNzb3JcIjozLFwiZm9ybWF0XCI6e1wiaWRcIjpcIm51bWJlclwifSxcInBhcmFtc1wiOnt9LFwiYWdnVHlwZVwiOlwiY291bnRcIn1dLFwiYnVja2V0c1wiOlt7XCJhY2Nlc3NvclwiOjAsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJzdHJpbmdcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifSx7XCJhY2Nlc3NvclwiOjEsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJudW1iZXJcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifSx7XCJhY2Nlc3NvclwiOjIsXCJmb3JtYXRcIjp7XCJpZFwiOlwidGVybXNcIixcInBhcmFtc1wiOntcImlkXCI6XCJzdHJpbmdcIixcIm90aGVyQnVja2V0TGFiZWxcIjpcIk90aGVyXCIsXCJtaXNzaW5nQnVja2V0TGFiZWxcIjpcIk1pc3NpbmdcIn19LFwicGFyYW1zXCI6e30sXCJhZ2dUeXBlXCI6XCJ0ZXJtc1wifV19fSxcImFnZ3NcIjpbe1wiaWRcIjpcIjFcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwiY291bnRcIixcInNjaGVtYVwiOlwibWV0cmljXCIsXCJwYXJhbXNcIjp7fX0se1wiaWRcIjpcIjNcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwidGVybXNcIixcInNjaGVtYVwiOlwiYnVja2V0XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwicnVsZS5uaXN0XzgwMF81M1wiLFwib3JkZXJCeVwiOlwiMVwiLFwib3JkZXJcIjpcImRlc2NcIixcInNpemVcIjoyMCxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCIsXCJjdXN0b21MYWJlbFwiOlwiUmVxdWlyZW1lbnRcIn19LHtcImlkXCI6XCI0XCIsXCJlbmFibGVkXCI6dHJ1ZSxcInR5cGVcIjpcInRlcm1zXCIsXCJzY2hlbWFcIjpcImJ1Y2tldFwiLFwicGFyYW1zXCI6e1wiZmllbGRcIjpcInJ1bGUubGV2ZWxcIixcIm9yZGVyQnlcIjpcIjFcIixcIm9yZGVyXCI6XCJkZXNjXCIsXCJzaXplXCI6NSxcIm90aGVyQnVja2V0XCI6ZmFsc2UsXCJvdGhlckJ1Y2tldExhYmVsXCI6XCJPdGhlclwiLFwibWlzc2luZ0J1Y2tldFwiOmZhbHNlLFwibWlzc2luZ0J1Y2tldExhYmVsXCI6XCJNaXNzaW5nXCIsXCJjdXN0b21MYWJlbFwiOlwiUnVsZSBsZXZlbFwifX0se1wiaWRcIjpcIjVcIixcImVuYWJsZWRcIjp0cnVlLFwidHlwZVwiOlwidGVybXNcIixcInNjaGVtYVwiOlwiYnVja2V0XCIsXCJwYXJhbXNcIjp7XCJmaWVsZFwiOlwicnVsZS5kZXNjcmlwdGlvblwiLFwib3JkZXJCeVwiOlwiMVwiLFwib3JkZXJcIjpcImRlc2NcIixcInNpemVcIjoyMDAsXCJvdGhlckJ1Y2tldFwiOmZhbHNlLFwib3RoZXJCdWNrZXRMYWJlbFwiOlwiT3RoZXJcIixcIm1pc3NpbmdCdWNrZXRcIjpmYWxzZSxcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOlwiTWlzc2luZ1wiLFwiY3VzdG9tTGFiZWxcIjpcIkRlc2NyaXB0aW9uXCJ9fV19JyxcbiAgICAgIHVpU3RhdGVKU09OOlxuICAgICAgICAne1widmlzXCI6e1wicGFyYW1zXCI6e1wic29ydFwiOntcImNvbHVtbkluZGV4XCI6MyxcImRpcmVjdGlvblwiOlwiZGVzY1wifX19fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046XG4gICAgICAgICAgJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJxdWVyeVwiOlwiXCIsXCJsYW5ndWFnZVwiOlwibHVjZW5lXCJ9fSdcbiAgICAgIH1cbiAgICB9XG4gIH1cbl07XG4iXX0=