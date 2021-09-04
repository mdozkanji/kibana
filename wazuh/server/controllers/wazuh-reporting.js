"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhReportingCtrl = void 0;

var _path = _interopRequireDefault(require("path"));

var _fs = _interopRequireDefault(require("fs"));

var _wazuhModules = require("../../common/wazuh-modules");

var TimSort = _interopRequireWildcard(require("timsort"));

var _errorResponse = require("../lib/error-response");

var VulnerabilityRequest = _interopRequireWildcard(require("../lib/reporting/vulnerability-request"));

var OverviewRequest = _interopRequireWildcard(require("../lib/reporting/overview-request"));

var RootcheckRequest = _interopRequireWildcard(require("../lib/reporting/rootcheck-request"));

var PCIRequest = _interopRequireWildcard(require("../lib/reporting/pci-request"));

var GDPRRequest = _interopRequireWildcard(require("../lib/reporting/gdpr-request"));

var TSCRequest = _interopRequireWildcard(require("../lib/reporting/tsc-request"));

var AuditRequest = _interopRequireWildcard(require("../lib/reporting/audit-request"));

var SyscheckRequest = _interopRequireWildcard(require("../lib/reporting/syscheck-request"));

var _pciRequirementsPdfmake = _interopRequireDefault(require("../integration-files/pci-requirements-pdfmake"));

var _gdprRequirementsPdfmake = _interopRequireDefault(require("../integration-files/gdpr-requirements-pdfmake"));

var _tscRequirementsPdfmake = _interopRequireDefault(require("../integration-files/tsc-requirements-pdfmake"));

var _processStateEquivalence = _interopRequireDefault(require("../lib/process-state-equivalence"));

var _csvKeyEquivalence = require("../../common/csv-key-equivalence");

var _agentConfiguration = require("../lib/reporting/agent-configuration");

var _printer = require("../lib/reporting/printer");

var _logger = require("../lib/logger");

var _constants = require("../../common/constants");

var _filesystem = require("../lib/filesystem");

function _getRequireWildcardCache() { if (typeof WeakMap !== "function") return null; var cache = new WeakMap(); _getRequireWildcardCache = function () { return cache; }; return cache; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/*
 * Wazuh app - Class for Wazuh reporting controller
 * Copyright (C) 2015-2021 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
class WazuhReportingCtrl {
  constructor() {}
  /**
   * This do format to filters
   * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
   * @param {String} searchBar search term
   */


  sanitizeKibanaFilters(filters, searchBar) {
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `Started to sanitize filters`, 'info');
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `filters: ${filters.length}, searchBar: ${searchBar}`, 'debug');
    let str = '';
    const agentsFilter = []; //separate agents filter

    filters = filters.filter(filter => {
      if (filter.meta.controlledBy === _constants.AUTHORIZED_AGENTS) {
        agentsFilter.push(filter);
        return false;
      }

      return filter;
    });
    const len = filters.length;

    for (let i = 0; i < len; i++) {
      const {
        negate,
        key,
        value,
        params,
        type
      } = filters[i].meta;
      str += `${negate ? 'NOT ' : ''}`;
      str += `${key}: `;
      str += `${type === 'range' ? `${params.gte}-${params.lt}` : !!value ? value : (params || {}).query}`;
      str += `${i === len - 1 ? '' : ' AND '}`;
    }

    if (searchBar) {
      str += ' AND ' + searchBar;
    }

    const agentsFilterStr = agentsFilter.map(filter => filter.meta.value).join(',');
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `str: ${str}, agentsFilterStr: ${agentsFilterStr}`, 'debug');
    return [str, agentsFilterStr];
  }
  /**
   * This performs the rendering of given header
   * @param {String} printer section target
   * @param {String} section section target
   * @param {Object} tab tab target
   * @param {Boolean} isAgents is agents section
   * @param {String} apiId ID of API
   */


  async renderHeader(context, printer, section, tab, isAgents, apiId) {
    try {
      (0, _logger.log)('reporting:renderHeader', `section: ${section}, tab: ${tab}, isAgents: ${isAgents}, apiId: ${apiId}`, 'debug');

      if (section && typeof section === 'string') {
        if (!['agentConfig', 'groupConfig'].includes(section)) {
          printer.addContent({
            text: _wazuhModules.WAZUH_MODULES[tab].title + ' report',
            style: 'h1'
          });
        } else if (section === 'agentConfig') {
          printer.addContent({
            text: `Agent ${isAgents} configuration`,
            style: 'h1'
          });
        } else if (section === 'groupConfig') {
          printer.addContent({
            text: 'Agents in group',
            style: {
              fontSize: 14,
              color: '#000'
            },
            margin: [0, 20, 0, 0]
          });

          if (section === 'groupConfig' && !Object.keys(isAgents).length) {
            printer.addContent({
              text: 'There are still no agents in this group.',
              style: {
                fontSize: 12,
                color: '#000'
              },
              margin: [0, 10, 0, 0]
            });
          }
        }

        printer.addNewLine();
      }

      if (isAgents && typeof isAgents === 'object') {
        await this.buildAgentsTable(context, printer, isAgents, apiId, section === 'groupConfig' ? tab : false);
      }

      if (isAgents && typeof isAgents === 'string') {
        const agentResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents`, {
          params: {
            agents_list: isAgents
          }
        }, {
          apiHostID: apiId
        });
        const agentData = agentResponse.data.data.affected_items[0];

        if (agentData && agentData.status !== 'active') {
          printer.addContentWithNewLine({
            text: `Warning. Agent is ${agentData.status.toLowerCase()}`,
            style: 'standard'
          });
        }

        await this.buildAgentsTable(context, printer, [isAgents], apiId);

        if (agentData && agentData.group) {
          const agentGroups = agentData.group.join(', ');
          printer.addContentWithNewLine({
            text: `Group${agentData.group.length > 1 ? 's' : ''}: ${agentGroups}`,
            style: 'standard'
          });
        }
      }

      if (_wazuhModules.WAZUH_MODULES[tab] && _wazuhModules.WAZUH_MODULES[tab].description) {
        printer.addContentWithNewLine({
          text: _wazuhModules.WAZUH_MODULES[tab].description,
          style: 'standard'
        });
      }

      return;
    } catch (error) {
      (0, _logger.log)('reporting:renderHeader', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * This build the agents table
   * @param {Array<Strings>} ids ids of agents
   * @param {String} apiId API id
   */


  async buildAgentsTable(context, printer, agentIDs, apiId, multi = false) {
    if (!agentIDs || !agentIDs.length) return;
    (0, _logger.log)('reporting:buildAgentsTable', `${agentIDs.length} agents for API ${apiId}`, 'info');

    try {
      let agentRows = [];

      if (multi) {
        try {
          const agentsResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/groups/${multi}/agents`, {}, {
            apiHostID: apiId
          });
          const agentsData = agentsResponse && agentsResponse.data && agentsResponse.data.data && agentsResponse.data.data.affected_items;
          agentRows = (agentsData || []).map(agent => ({ ...agent,
            manager: agent.manager || agent.manager_host,
            os: agent.os && agent.os.name && agent.os.version ? `${agent.os.name} ${agent.os.version}` : ''
          }));
        } catch (error) {
          (0, _logger.log)('reporting:buildAgentsTable', `Skip agent due to: ${error.message || error}`, 'debug');
        }
      } else {
        for (const agentID of agentIDs) {
          try {
            const agentResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents`, {
              params: {
                q: `id=${agentID}`
              }
            }, {
              apiHostID: apiId
            });
            const [agent] = agentResponse.data.data.affected_items;
            agentRows.push({ ...agent,
              manager: agent.manager || agent.manager_host,
              os: agent.os && agent.os.name && agent.os.version ? `${agent.os.name} ${agent.os.version}` : ''
            });
          } catch (error) {
            (0, _logger.log)('reporting:buildAgentsTable', `Skip agent due to: ${error.message || error}`, 'debug');
          }
        }
      }

      printer.addSimpleTable({
        columns: [{
          id: 'id',
          label: 'ID'
        }, {
          id: 'name',
          label: 'Name'
        }, {
          id: 'ip',
          label: 'IP'
        }, {
          id: 'version',
          label: 'Version'
        }, {
          id: 'manager',
          label: 'Manager'
        }, {
          id: 'os',
          label: 'OS'
        }, {
          id: 'dateAdd',
          label: 'Registration date'
        }, {
          id: 'lastKeepAlive',
          label: 'Last keep alive'
        }],
        items: agentRows
      });
    } catch (error) {
      (0, _logger.log)('reporting:buildAgentsTable', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * This load more information
   * @param {*} context Endpoint context
   * @param {*} printer printer instance
   * @param {String} section section target
   * @param {Object} tab tab target
   * @param {String} apiId ID of API
   * @param {Number} from Timestamp (ms) from
   * @param {Number} to Timestamp (ms) to
   * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
   * @param {String} pattern
   * @param {Object} agent agent target
   * @returns {Object} Extended information
   */


  async extendedInformation(context, printer, section, tab, apiId, from, to, filters, pattern = _constants.WAZUH_ALERTS_PATTERN, agent = null) {
    try {
      (0, _logger.log)('reporting:extendedInformation', `Section ${section} and tab ${tab}, API is ${apiId}. From ${from} to ${to}. Filters ${filters}. Index pattern ${pattern}`, 'info');

      if (section === 'agents' && !agent) {
        throw new Error('Reporting for specific agent needs an agent ID in order to work properly');
      }

      const agents = await context.wazuh.api.client.asCurrentUser.request('GET', '/agents', {
        params: {
          limit: 1
        }
      }, {
        apiHostID: apiId
      });
      const totalAgents = agents.data.data.total_affected_items;

      if (section === 'overview' && tab === 'vuls') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching overview vulnerability detector metrics', 'debug');
        const vulnerabilitiesLevels = ['Low', 'Medium', 'High', 'Critical'];
        const vulnerabilitiesResponsesCount = (await Promise.all(vulnerabilitiesLevels.map(async vulnerabilitiesLevel => {
          try {
            const count = await VulnerabilityRequest.uniqueSeverityCount(context, from, to, vulnerabilitiesLevel, filters, pattern);
            return count ? `${count} of ${totalAgents} agents have ${vulnerabilitiesLevel.toLocaleLowerCase()} vulnerabilities.` : undefined;
          } catch (error) {}
        }))).filter(vulnerabilitiesResponse => vulnerabilitiesResponse);
        printer.addList({
          title: {
            text: 'Summary',
            style: 'h2'
          },
          list: vulnerabilitiesResponsesCount
        });
        (0, _logger.log)('reporting:extendedInformation', 'Fetching overview vulnerability detector top 3 agents by category', 'debug');
        const lowRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'Low', filters, pattern);
        const mediumRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'Medium', filters, pattern);
        const highRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'High', filters, pattern);
        const criticalRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'Critical', filters, pattern);
        (0, _logger.log)('reporting:extendedInformation', 'Adding overview vulnerability detector top 3 agents by category', 'debug');

        if (criticalRank && criticalRank.length) {
          printer.addContentWithNewLine({
            text: 'Top 3 agents with critical severity vulnerabilities',
            style: 'h3'
          });
          await this.buildAgentsTable(context, printer, criticalRank, apiId);
          printer.addNewLine();
        }

        if (highRank && highRank.length) {
          printer.addContentWithNewLine({
            text: 'Top 3 agents with high severity vulnerabilities',
            style: 'h3'
          });
          await this.buildAgentsTable(context, printer, highRank, apiId);
          printer.addNewLine();
        }

        if (mediumRank && mediumRank.length) {
          printer.addContentWithNewLine({
            text: 'Top 3 agents with medium severity vulnerabilities',
            style: 'h3'
          });
          await this.buildAgentsTable(context, printer, mediumRank, apiId);
          printer.addNewLine();
        }

        if (lowRank && lowRank.length) {
          printer.addContentWithNewLine({
            text: 'Top 3 agents with low severity vulnerabilities',
            style: 'h3'
          });
          await this.buildAgentsTable(context, printer, lowRank, apiId);
          printer.addNewLine();
        }

        (0, _logger.log)('reporting:extendedInformation', 'Fetching overview vulnerability detector top 3 CVEs', 'debug');
        const cveRank = await VulnerabilityRequest.topCVECount(context, from, to, filters, pattern);
        (0, _logger.log)('reporting:extendedInformation', 'Adding overview vulnerability detector top 3 CVEs', 'debug');

        if (cveRank && cveRank.length) {
          printer.addSimpleTable({
            title: {
              text: 'Top 3 CVE',
              style: 'h2'
            },
            columns: [{
              id: 'top',
              label: 'Top'
            }, {
              id: 'cve',
              label: 'CVE'
            }],
            items: cveRank.map(item => ({
              top: cveRank.indexOf(item) + 1,
              cve: item
            }))
          });
        }
      }

      if (section === 'overview' && tab === 'general') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching top 3 agents with level 15 alerts', 'debug');
        const level15Rank = await OverviewRequest.topLevel15(context, from, to, filters, pattern);
        (0, _logger.log)('reporting:extendedInformation', 'Adding top 3 agents with level 15 alerts', 'debug');

        if (level15Rank.length) {
          printer.addContent({
            text: 'Top 3 agents with level 15 alerts',
            style: 'h2'
          });
          await this.buildAgentsTable(context, printer, level15Rank, apiId);
        }
      }

      if (section === 'overview' && tab === 'pm') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching most common rootkits', 'debug');
        const top5RootkitsRank = await RootcheckRequest.top5RootkitsDetected(context, from, to, filters, pattern);
        (0, _logger.log)('reporting:extendedInformation', 'Adding most common rootkits', 'debug');

        if (top5RootkitsRank && top5RootkitsRank.length) {
          printer.addContentWithNewLine({
            text: 'Most common rootkits found among your agents',
            style: 'h2'
          }).addContentWithNewLine({
            text: 'Rootkits are a set of software tools that enable an unauthorized user to gain control of a computer system without being detected.',
            style: 'standard'
          }).addSimpleTable({
            items: top5RootkitsRank.map(item => {
              return {
                top: top5RootkitsRank.indexOf(item) + 1,
                name: item
              };
            }),
            columns: [{
              id: 'top',
              label: 'Top'
            }, {
              id: 'name',
              label: 'Rootkit'
            }]
          });
        }

        (0, _logger.log)('reporting:extendedInformation', 'Fetching hidden pids', 'debug');
        const hiddenPids = await RootcheckRequest.agentsWithHiddenPids(context, from, to, filters, pattern);
        hiddenPids && printer.addContent({
          text: `${hiddenPids} of ${totalAgents} agents have hidden processes`,
          style: 'h3'
        });
        !hiddenPids && printer.addContentWithNewLine({
          text: `No agents have hidden processes`,
          style: 'h3'
        });
        const hiddenPorts = await RootcheckRequest.agentsWithHiddenPorts(context, from, to, filters, pattern);
        hiddenPorts && printer.addContent({
          text: `${hiddenPorts} of ${totalAgents} agents have hidden ports`,
          style: 'h3'
        });
        !hiddenPorts && printer.addContent({
          text: `No agents have hidden ports`,
          style: 'h3'
        });
        printer.addNewLine();
      }

      if (['overview', 'agents'].includes(section) && tab === 'pci') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching top PCI DSS requirements', 'debug');
        const topPciRequirements = await PCIRequest.topPCIRequirements(context, from, to, filters, pattern);
        printer.addContentWithNewLine({
          text: 'Most common PCI DSS requirements alerts found',
          style: 'h2'
        });

        for (const item of topPciRequirements) {
          const rules = await PCIRequest.getRulesByRequirement(context, from, to, filters, item, pattern);
          printer.addContentWithNewLine({
            text: `Requirement ${item}`,
            style: 'h3'
          });

          if (_pciRequirementsPdfmake.default[item]) {
            const content = typeof _pciRequirementsPdfmake.default[item] === 'string' ? {
              text: _pciRequirementsPdfmake.default[item],
              style: 'standard'
            } : _pciRequirementsPdfmake.default[item];
            printer.addContentWithNewLine(content);
          }

          rules && rules.length && printer.addSimpleTable({
            columns: [{
              id: 'ruleId',
              label: 'Rule ID'
            }, {
              id: 'ruleDescription',
              label: 'Description'
            }],
            items: rules,
            title: `Top rules for ${item} requirement`
          });
        }
      }

      if (['overview', 'agents'].includes(section) && tab === 'tsc') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching top TSC requirements', 'debug');
        const topTSCRequirements = await TSCRequest.topTSCRequirements(context, from, to, filters, pattern);
        printer.addContentWithNewLine({
          text: 'Most common TSC requirements alerts found',
          style: 'h2'
        });

        for (const item of topTSCRequirements) {
          const rules = await TSCRequest.getRulesByRequirement(context, from, to, filters, item, pattern);
          printer.addContentWithNewLine({
            text: `Requirement ${item}`,
            style: 'h3'
          });

          if (_tscRequirementsPdfmake.default[item]) {
            const content = typeof _tscRequirementsPdfmake.default[item] === 'string' ? {
              text: _tscRequirementsPdfmake.default[item],
              style: 'standard'
            } : _tscRequirementsPdfmake.default[item];
            printer.addContentWithNewLine(content);
          }

          rules && rules.length && printer.addSimpleTable({
            columns: [{
              id: 'ruleId',
              label: 'Rule ID'
            }, {
              id: 'ruleDescription',
              label: 'Description'
            }],
            items: rules,
            title: `Top rules for ${item} requirement`
          });
        }
      }

      if (['overview', 'agents'].includes(section) && tab === 'gdpr') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching top GDPR requirements', 'debug');
        const topGdprRequirements = await GDPRRequest.topGDPRRequirements(context, from, to, filters, pattern);
        printer.addContentWithNewLine({
          text: 'Most common GDPR requirements alerts found',
          style: 'h2'
        });

        for (const item of topGdprRequirements) {
          const rules = await GDPRRequest.getRulesByRequirement(context, from, to, filters, item, pattern);
          printer.addContentWithNewLine({
            text: `Requirement ${item}`,
            style: 'h3'
          });

          if (_gdprRequirementsPdfmake.default && _gdprRequirementsPdfmake.default[item]) {
            const content = typeof _gdprRequirementsPdfmake.default[item] === 'string' ? {
              text: _gdprRequirementsPdfmake.default[item],
              style: 'standard'
            } : _gdprRequirementsPdfmake.default[item];
            printer.addContentWithNewLine(content);
          }

          rules && rules.length && printer.addSimpleTable({
            columns: [{
              id: 'ruleId',
              label: 'Rule ID'
            }, {
              id: 'ruleDescription',
              label: 'Description'
            }],
            items: rules,
            title: `Top rules for ${item} requirement`
          });
        }

        printer.addNewLine();
      }

      if (section === 'overview' && tab === 'audit') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching agents with high number of failed sudo commands', 'debug');
        const auditAgentsNonSuccess = await AuditRequest.getTop3AgentsSudoNonSuccessful(context, from, to, filters, pattern);

        if (auditAgentsNonSuccess && auditAgentsNonSuccess.length) {
          printer.addContent({
            text: 'Agents with high number of failed sudo commands',
            style: 'h2'
          });
          await this.buildAgentsTable(context, printer, auditAgentsNonSuccess, apiId);
        }

        const auditAgentsFailedSyscall = await AuditRequest.getTop3AgentsFailedSyscalls(context, from, to, filters, pattern);

        if (auditAgentsFailedSyscall && auditAgentsFailedSyscall.length) {
          printer.addSimpleTable({
            columns: [{
              id: 'agent',
              label: 'Agent ID'
            }, {
              id: 'syscall_id',
              label: 'Syscall ID'
            }, {
              id: 'syscall_syscall',
              label: 'Syscall'
            }],
            items: auditAgentsFailedSyscall.map(item => ({
              agent: item.agent,
              syscall_id: item.syscall.id,
              syscall_syscall: item.syscall.syscall
            })),
            title: {
              text: 'Most common failing syscalls',
              style: 'h2'
            }
          });
        }
      }

      if (section === 'overview' && tab === 'fim') {
        (0, _logger.log)('reporting:extendedInformation', 'Fetching top 3 rules for FIM', 'debug');
        const rules = await SyscheckRequest.top3Rules(context, from, to, filters, pattern);

        if (rules && rules.length) {
          printer.addContentWithNewLine({
            text: 'Top 3 FIM rules',
            style: 'h2'
          }).addSimpleTable({
            columns: [{
              id: 'ruleId',
              label: 'Rule ID'
            }, {
              id: 'ruleDescription',
              label: 'Description'
            }],
            items: rules,
            title: {
              text: 'Top 3 rules that are generating most alerts.',
              style: 'standard'
            }
          });
        }

        (0, _logger.log)('reporting:extendedInformation', 'Fetching top 3 agents for FIM', 'debug');
        const agents = await SyscheckRequest.top3agents(context, from, to, filters, pattern);

        if (agents && agents.length) {
          printer.addContentWithNewLine({
            text: 'Agents with suspicious FIM activity',
            style: 'h2'
          });
          printer.addContentWithNewLine({
            text: 'Top 3 agents that have most FIM alerts from level 7 to level 15. Take care about them.',
            style: 'standard'
          });
          await this.buildAgentsTable(context, printer, agents, apiId);
        }
      }

      if (section === 'agents' && tab === 'audit') {
        (0, _logger.log)('reporting:extendedInformation', `Fetching most common failed syscalls`, 'debug');
        const auditFailedSyscall = await AuditRequest.getTopFailedSyscalls(context, from, to, filters, pattern);
        auditFailedSyscall && auditFailedSyscall.length && printer.addSimpleTable({
          columns: [{
            id: 'id',
            label: 'id'
          }, {
            id: 'syscall',
            label: 'Syscall'
          }],
          items: auditFailedSyscall,
          title: 'Most common failing syscalls'
        });
      }

      if (section === 'agents' && tab === 'fim') {
        (0, _logger.log)('reporting:extendedInformation', `Fetching syscheck database for agent ${agent}`, 'debug');
        const lastScanResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/syscheck/${agent}/last_scan`, {}, {
          apiHostID: apiId
        });

        if (lastScanResponse && lastScanResponse.data) {
          const lastScanData = lastScanResponse.data.data.affected_items[0];

          if (lastScanData.start && lastScanData.end) {
            printer.addContent({
              text: `Last file integrity monitoring scan was executed from ${lastScanData.start} to ${lastScanData.end}.`
            });
          } else if (lastScanData.start) {
            printer.addContent({
              text: `File integrity monitoring scan is currently in progress for this agent (started on ${lastScanData.start}).`
            });
          } else {
            printer.addContent({
              text: `File integrity monitoring scan is currently in progress for this agent.`
            });
          }

          printer.addNewLine();
        }

        (0, _logger.log)('reporting:extendedInformation', `Fetching last 10 deleted files for FIM`, 'debug');
        const lastTenDeleted = await SyscheckRequest.lastTenDeletedFiles(context, from, to, filters, pattern);
        lastTenDeleted && lastTenDeleted.length && printer.addSimpleTable({
          columns: [{
            id: 'path',
            label: 'Path'
          }, {
            id: 'date',
            label: 'Date'
          }],
          items: lastTenDeleted,
          title: 'Last 10 deleted files'
        });
        (0, _logger.log)('reporting:extendedInformation', `Fetching last 10 modified files`, 'debug');
        const lastTenModified = await SyscheckRequest.lastTenModifiedFiles(context, from, to, filters, pattern);
        lastTenModified && lastTenModified.length && printer.addSimpleTable({
          columns: [{
            id: 'path',
            label: 'Path'
          }, {
            id: 'date',
            label: 'Date'
          }],
          items: lastTenModified,
          title: 'Last 10 modified files'
        });
      }

      if (section === 'agents' && tab === 'syscollector') {
        (0, _logger.log)('reporting:extendedInformation', `Fetching hardware information for agent ${agent}`, 'debug');
        const requestsSyscollectorLists = [{
          endpoint: `/syscollector/${agent}/hardware`,
          loggerMessage: `Fetching Hardware information for agent ${agent}`,
          list: {
            title: {
              text: 'Hardware information',
              style: 'h2'
            }
          },
          mapResponse: hardware => [hardware.cpu && hardware.cpu.cores && `${hardware.cpu.cores} cores`, hardware.cpu && hardware.cpu.name, hardware.ram && hardware.ram.total && `${Number(hardware.ram.total / 1024 / 1024).toFixed(2)}GB RAM`]
        }, {
          endpoint: `/syscollector/${agent}/os`,
          loggerMessage: `Fetching OS information for agent ${agent}`,
          list: {
            title: {
              text: 'OS information',
              style: 'h2'
            }
          },
          mapResponse: osData => [osData.sysname, osData.version, osData.architecture, osData.release, osData.os && osData.os.name && osData.os.version && `${osData.os.name} ${osData.os.version}`]
        }];
        const syscollectorLists = await Promise.all(requestsSyscollectorLists.map(async requestSyscollector => {
          try {
            (0, _logger.log)('reporting:extendedInformation', requestSyscollector.loggerMessage, 'debug');
            const responseSyscollector = await context.wazuh.api.client.asCurrentUser.request('GET', requestSyscollector.endpoint, {}, {
              apiHostID: apiId
            });
            const [data] = responseSyscollector && responseSyscollector.data && responseSyscollector.data.data && responseSyscollector.data.data.affected_items || [];

            if (data) {
              return { ...requestSyscollector.list,
                list: requestSyscollector.mapResponse(data)
              };
            }
          } catch (error) {
            (0, _logger.log)('reporting:extendedInformation', error.message || error);
          }
        }));

        if (syscollectorLists) {
          syscollectorLists.filter(syscollectorList => syscollectorList).forEach(syscollectorList => printer.addList(syscollectorList));
        }

        const vulnerabilitiesRequests = ['Critical', 'High'];
        const vulnerabilitiesResponsesItems = (await Promise.all(vulnerabilitiesRequests.map(async vulnerabilitiesLevel => {
          try {
            (0, _logger.log)('reporting:extendedInformation', `Fetching top ${vulnerabilitiesLevel} packages`, 'debug');
            return await VulnerabilityRequest.topPackages(context, from, to, vulnerabilitiesLevel, filters, pattern);
          } catch (error) {
            (0, _logger.log)('reporting:extendedInformation', error.message || error);
          }
        }))).filter(vulnerabilitiesResponse => vulnerabilitiesResponse).flat();

        if (vulnerabilitiesResponsesItems && vulnerabilitiesResponsesItems.length) {
          printer.addSimpleTable({
            title: {
              text: 'Vulnerable packages found (last 24 hours)',
              style: 'h2'
            },
            columns: [{
              id: 'package',
              label: 'Package'
            }, {
              id: 'severity',
              label: 'Severity'
            }],
            items: vulnerabilitiesResponsesItems
          });
        }
      }

      if (section === 'agents' && tab === 'vuls') {
        const topCriticalPackages = await VulnerabilityRequest.topPackagesWithCVE(context, from, to, 'Critical', filters, pattern);

        if (topCriticalPackages && topCriticalPackages.length) {
          printer.addContentWithNewLine({
            text: 'Critical severity',
            style: 'h2'
          });
          printer.addContentWithNewLine({
            text: 'These vulnerabilties are critical, please review your agent. Click on each link to read more about each found vulnerability.',
            style: 'standard'
          });
          const customul = [];

          for (const critical of topCriticalPackages) {
            customul.push({
              text: critical.package,
              style: 'standard'
            });
            customul.push({
              ul: critical.references.map(item => ({
                text: item.substring(0, 80) + '...',
                link: item,
                color: '#1EA5C8'
              }))
            });
          }

          printer.addContentWithNewLine({
            ul: customul
          });
        }

        const topHighPackages = await VulnerabilityRequest.topPackagesWithCVE(context, from, to, 'High', filters, pattern);

        if (topHighPackages && topHighPackages.length) {
          printer.addContentWithNewLine({
            text: 'High severity',
            style: 'h2'
          });
          printer.addContentWithNewLine({
            text: 'Click on each link to read more about each found vulnerability.',
            style: 'standard'
          });
          const customul = [];

          for (const critical of topHighPackages) {
            customul.push({
              text: critical.package,
              style: 'standard'
            });
            customul.push({
              ul: critical.references.map(item => ({
                text: item,
                color: '#1EA5C8'
              }))
            });
          }

          customul && customul.length && printer.addContent({
            ul: customul
          });
          printer.addNewLine();
        }
      }

      return false;
    } catch (error) {
      (0, _logger.log)('reporting:extendedInformation', error.message || error);
      return Promise.reject(error);
    }
  }

  getConfigRows(data, labels) {
    (0, _logger.log)('reporting:getConfigRows', `Building configuration rows`, 'info');
    const result = [];

    for (let prop in data || []) {
      if (Array.isArray(data[prop])) {
        data[prop].forEach((x, idx) => {
          if (typeof x === 'object') data[prop][idx] = JSON.stringify(x);
        });
      }

      result.push([(labels || {})[prop] || _csvKeyEquivalence.KeyEquivalence[prop] || prop, data[prop] || '-']);
    }

    return result;
  }

  getConfigTables(data, section, tab, array = []) {
    (0, _logger.log)('reporting:getConfigTables', `Building configuration tables`, 'info');
    let plainData = {};
    const nestedData = [];
    const tableData = [];

    if (data.length === 1 && Array.isArray(data)) {
      tableData[section.config[tab].configuration] = data;
    } else {
      for (let key in data) {
        if (typeof data[key] !== 'object' && !Array.isArray(data[key]) || Array.isArray(data[key]) && typeof data[key][0] !== 'object') {
          plainData[key] = Array.isArray(data[key]) && typeof data[key][0] !== 'object' ? data[key].map(x => {
            return typeof x === 'object' ? JSON.stringify(x) : x + '\n';
          }) : data[key];
        } else if (Array.isArray(data[key]) && typeof data[key][0] === 'object') {
          tableData[key] = data[key];
        } else {
          if (section.isGroupConfig && ['pack', 'content'].includes(key)) {
            tableData[key] = [data[key]];
          } else {
            nestedData.push(data[key]);
          }
        }
      }
    }

    array.push({
      title: (section.options || {}).hideHeader ? '' : (section.tabs || [])[tab] || (section.isGroupConfig ? ((section.labels || [])[0] || [])[tab] : ''),
      columns: ['', ''],
      type: 'config',
      rows: this.getConfigRows(plainData, (section.labels || [])[0])
    });

    for (let key in tableData) {
      const columns = Object.keys(tableData[key][0]);
      columns.forEach((col, i) => {
        columns[i] = col[0].toUpperCase() + col.slice(1);
      });
      const rows = tableData[key].map(x => {
        let row = [];

        for (let key in x) {
          row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
            return x + '\n';
          }) : JSON.stringify(x[key]));
        }

        while (row.length < columns.length) {
          row.push('-');
        }

        return row;
      });
      array.push({
        title: ((section.labels || [])[0] || [])[key] || '',
        type: 'table',
        columns,
        rows
      });
    }

    nestedData.forEach(nest => {
      this.getConfigTables(nest, section, tab + 1, array);
    });
    return array;
  }
  /**
   * Create a report for the modules
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {*} reports list or ErrorResponse
   */


  async createReportsModules(context, request, response) {
    try {
      (0, _logger.log)('reporting:createReportsModules', `Report started`, 'info');
      const {
        array,
        agents,
        browserTimezone,
        searchBar,
        filters,
        time,
        tables,
        name,
        section
      } = request.body;
      const {
        moduleID
      } = request.params;
      const {
        id: apiId,
        pattern: indexPattern
      } = request.headers;
      const {
        from,
        to
      } = time || {}; // Init

      const printer = new _printer.ReportPrinter();
      const {
        username: userID
      } = await context.wazuh.security.getCurrentUser(request, context);
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID));
      await this.renderHeader(context, printer, section, moduleID, agents, apiId);
      const [sanitizedFilters, agentsFilter] = filters ? this.sanitizeKibanaFilters(filters, searchBar) : [false, false];

      if (time && sanitizedFilters) {
        printer.addTimeRangeAndFilters(from, to, sanitizedFilters, browserTimezone);
      }

      if (time) {
        await this.extendedInformation(context, printer, section, moduleID, apiId, new Date(from).getTime(), new Date(to).getTime(), sanitizedFilters, indexPattern, agents);
      }

      printer.addVisualizations(array, agents, moduleID);

      if (tables) {
        printer.addTables(tables);
      } //add authorized agents


      if (agentsFilter) {
        printer.addAgentsFilters(agentsFilter);
      }

      await printer.print(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID, name));
      return response.ok({
        body: {
          success: true,
          message: `Report ${name} was created`
        }
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
    }
  }
  /**
   * Create a report for the groups
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {*} reports list or ErrorResponse
   */


  async createReportsGroups(context, request, response) {
    try {
      (0, _logger.log)('reporting:createReportsGroups', `Report started`, 'info');
      const {
        browserTimezone,
        searchBar,
        filters,
        time,
        name,
        components
      } = request.body;
      const {
        groupID
      } = request.params;
      const {
        id: apiId,
        pattern: indexPattern
      } = request.headers;
      const {
        from,
        to
      } = time || {}; // Init

      const printer = new _printer.ReportPrinter();
      const {
        username: userID
      } = await context.wazuh.security.getCurrentUser(request, context);
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID));
      let tables = [];
      const equivalences = {
        localfile: 'Local files',
        osquery: 'Osquery',
        command: 'Command',
        syscheck: 'Syscheck',
        'open-scap': 'OpenSCAP',
        'cis-cat': 'CIS-CAT',
        syscollector: 'Syscollector',
        rootcheck: 'Rootcheck',
        labels: 'Labels',
        sca: 'Security configuration assessment'
      };
      printer.addContent({
        text: `Group ${groupID} configuration`,
        style: 'h1'
      });

      if (components['0']) {
        let configuration = {};

        try {
          const configurationResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/groups/${groupID}/configuration`, {}, {
            apiHostID: apiId
          });
          configuration = configurationResponse.data.data;
        } catch (error) {
          (0, _logger.log)('reporting:createReportsGroups', error.message || error, 'debug');
        }

        if (configuration.affected_items.length > 0 && Object.keys(configuration.affected_items[0].config).length) {
          printer.addContent({
            text: 'Configurations',
            style: {
              fontSize: 14,
              color: '#000'
            },
            margin: [0, 10, 0, 15]
          });
          const section = {
            labels: [],
            isGroupConfig: true
          };

          for (let config of configuration.affected_items) {
            let filterTitle = '';
            let index = 0;

            for (let filter of Object.keys(config.filters)) {
              filterTitle = filterTitle.concat(`${filter}: ${config.filters[filter]}`);

              if (index < Object.keys(config.filters).length - 1) {
                filterTitle = filterTitle.concat(' | ');
              }

              index++;
            }

            printer.addContent({
              text: filterTitle,
              style: 'h4',
              margin: [0, 0, 0, 10]
            });
            let idx = 0;
            section.tabs = [];

            for (let _d of Object.keys(config.config)) {
              for (let c of _agentConfiguration.AgentConfiguration.configurations) {
                for (let s of c.sections) {
                  section.opts = s.opts || {};

                  for (let cn of s.config || []) {
                    if (cn.configuration === _d) {
                      section.labels = s.labels || [[]];
                    }
                  }

                  for (let wo of s.wodle || []) {
                    if (wo.name === _d) {
                      section.labels = s.labels || [[]];
                    }
                  }
                }
              }

              section.labels[0]['pack'] = 'Packs';
              section.labels[0]['content'] = 'Evaluations';
              section.labels[0]['7'] = 'Scan listening netwotk ports';
              section.tabs.push(equivalences[_d]);

              if (Array.isArray(config.config[_d])) {
                /* LOG COLLECTOR */
                if (_d === 'localfile') {
                  let groups = [];

                  config.config[_d].forEach(obj => {
                    if (!groups[obj.logformat]) {
                      groups[obj.logformat] = [];
                    }

                    groups[obj.logformat].push(obj);
                  });

                  Object.keys(groups).forEach(group => {
                    let saveidx = 0;
                    groups[group].forEach((x, i) => {
                      if (Object.keys(x).length > Object.keys(groups[group][saveidx]).length) {
                        saveidx = i;
                      }
                    });
                    const columns = Object.keys(groups[group][saveidx]);
                    const rows = groups[group].map(x => {
                      let row = [];
                      columns.forEach(key => {
                        row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
                          return x + '\n';
                        }) : JSON.stringify(x[key]));
                      });
                      return row;
                    });
                    columns.forEach((col, i) => {
                      columns[i] = col[0].toUpperCase() + col.slice(1);
                    });
                    tables.push({
                      title: 'Local files',
                      type: 'table',
                      columns,
                      rows
                    });
                  });
                } else if (_d === 'labels') {
                  const obj = config.config[_d][0].label;
                  const columns = Object.keys(obj[0]);

                  if (!columns.includes('hidden')) {
                    columns.push('hidden');
                  }

                  const rows = obj.map(x => {
                    let row = [];
                    columns.forEach(key => {
                      row.push(x[key]);
                    });
                    return row;
                  });
                  columns.forEach((col, i) => {
                    columns[i] = col[0].toUpperCase() + col.slice(1);
                  });
                  tables.push({
                    title: 'Labels',
                    type: 'table',
                    columns,
                    rows
                  });
                } else {
                  for (let _d2 of config.config[_d]) {
                    tables.push(...this.getConfigTables(_d2, section, idx));
                  }
                }
              } else {
                /*INTEGRITY MONITORING MONITORED DIRECTORIES */
                if (config.config[_d].directories) {
                  const directories = config.config[_d].directories;
                  delete config.config[_d].directories;
                  tables.push(...this.getConfigTables(config.config[_d], section, idx));
                  let diffOpts = [];
                  Object.keys(section.opts).forEach(x => {
                    diffOpts.push(x);
                  });
                  const columns = ['', ...diffOpts.filter(x => x !== 'check_all' && x !== 'check_sum')];
                  let rows = [];
                  directories.forEach(x => {
                    let row = [];
                    row.push(x.path);
                    columns.forEach(y => {
                      if (y !== '') {
                        y = y !== 'check_whodata' ? y : 'whodata';
                        row.push(x[y] ? x[y] : 'no');
                      }
                    });
                    row.push(x.recursion_level);
                    rows.push(row);
                  });
                  columns.forEach((x, idx) => {
                    columns[idx] = section.opts[x];
                  });
                  columns.push('RL');
                  tables.push({
                    title: 'Monitored directories',
                    type: 'table',
                    columns,
                    rows
                  });
                } else {
                  tables.push(...this.getConfigTables(config.config[_d], section, idx));
                }
              }

              for (const table of tables) {
                printer.addConfigTables([table]);
              }

              idx++;
              tables = [];
            }

            tables = [];
          }
        } else {
          printer.addContent({
            text: 'A configuration for this group has not yet been set up.',
            style: {
              fontSize: 12,
              color: '#000'
            },
            margin: [0, 10, 0, 15]
          });
        }
      }

      if (components['1']) {
        let agentsInGroup = [];

        try {
          const agentsInGroupResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/groups/${groupID}/agents`, {}, {
            apiHostID: apiId
          });
          agentsInGroup = agentsInGroupResponse.data.data.affected_items;
        } catch (error) {
          (0, _logger.log)('reporting:report', error.message || error, 'debug');
        }

        await this.renderHeader(context, printer, 'groupConfig', groupID, (agentsInGroup || []).map(x => x.id), apiId);
      }

      await printer.print(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID, name));
      return response.ok({
        body: {
          success: true,
          message: `Report ${name} was created`
        }
      });
    } catch (error) {
      (0, _logger.log)('reporting:createReportsGroups', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
    }
  }
  /**
   * Create a report for the agents
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {*} reports list or ErrorResponse
   */


  async createReportsAgents(context, request, response) {
    try {
      (0, _logger.log)('reporting:createReportsAgents', `Report started`, 'info');
      const {
        browserTimezone,
        searchBar,
        filters,
        time,
        name,
        components
      } = request.body;
      const {
        agentID
      } = request.params;
      const {
        id: apiId
      } = request.headers;
      const {
        from,
        to
      } = time || {};
      const printer = new _printer.ReportPrinter();
      const {
        username: userID
      } = await context.wazuh.security.getCurrentUser(request, context);
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID));
      let wmodulesResponse = {};
      let tables = [];

      try {
        wmodulesResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents/${agentID}/config/wmodules/wmodules`, {}, {
          apiHostID: apiId
        });
      } catch (error) {
        (0, _logger.log)('reporting:report', error.message || error, 'debug');
      }

      await this.renderHeader(context, printer, 'agentConfig', 'agentConfig', agentID, apiId);
      let idxComponent = 0;

      for (let config of _agentConfiguration.AgentConfiguration.configurations) {
        let titleOfSection = false;
        (0, _logger.log)('reporting:createReportsAgents', `Iterate over ${config.sections.length} configuration sections`, 'debug');

        for (let section of config.sections) {
          if (components[idxComponent] && (section.config || section.wodle)) {
            let idx = 0;
            const configs = (section.config || []).concat(section.wodle || []);
            (0, _logger.log)('reporting:createReportsAgents', `Iterate over ${configs.length} configuration blocks`, 'debug');

            for (let conf of configs) {
              let agentConfigResponse = {};

              try {
                if (!conf['name']) {
                  agentConfigResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents/${agentID}/config/${conf.component}/${conf.configuration}`, {}, {
                    apiHostID: apiId
                  });
                } else {
                  for (let wodle of wmodulesResponse.data.data['wmodules']) {
                    if (Object.keys(wodle)[0] === conf['name']) {
                      agentConfigResponse.data = {
                        data: wodle
                      };
                    }
                  }
                }

                const agentConfig = agentConfigResponse && agentConfigResponse.data && agentConfigResponse.data.data;

                if (!titleOfSection) {
                  printer.addContent({
                    text: config.title,
                    style: 'h1',
                    margin: [0, 0, 0, 15]
                  });
                  titleOfSection = true;
                }

                printer.addContent({
                  text: section.subtitle,
                  style: 'h4'
                });
                printer.addContent({
                  text: section.desc,
                  style: {
                    fontSize: 12,
                    color: '#000'
                  },
                  margin: [0, 0, 0, 10]
                });

                if (agentConfig) {
                  for (let agentConfigKey of Object.keys(agentConfig)) {
                    if (Array.isArray(agentConfig[agentConfigKey])) {
                      /* LOG COLLECTOR */
                      if (conf.filterBy) {
                        let groups = [];
                        agentConfig[agentConfigKey].forEach(obj => {
                          if (!groups[obj.logformat]) {
                            groups[obj.logformat] = [];
                          }

                          groups[obj.logformat].push(obj);
                        });
                        Object.keys(groups).forEach(group => {
                          let saveidx = 0;
                          groups[group].forEach((x, i) => {
                            if (Object.keys(x).length > Object.keys(groups[group][saveidx]).length) {
                              saveidx = i;
                            }
                          });
                          const columns = Object.keys(groups[group][saveidx]);
                          const rows = groups[group].map(x => {
                            let row = [];
                            columns.forEach(key => {
                              row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
                                return x + '\n';
                              }) : JSON.stringify(x[key]));
                            });
                            return row;
                          });
                          columns.forEach((col, i) => {
                            columns[i] = col[0].toUpperCase() + col.slice(1);
                          });
                          tables.push({
                            title: section.labels[0][group],
                            type: 'table',
                            columns,
                            rows
                          });
                        });
                      } else if (agentConfigKey.configuration !== 'socket') {
                        tables.push(...this.getConfigTables(agentConfig[agentConfigKey], section, idx));
                      } else {
                        for (let _d2 of agentConfig[agentConfigKey]) {
                          tables.push(...this.getConfigTables(_d2, section, idx));
                        }
                      }
                    } else {
                      /*INTEGRITY MONITORING MONITORED DIRECTORIES */
                      if (conf.matrix) {
                        const directories = agentConfig[agentConfigKey].directories;
                        delete agentConfig[agentConfigKey].directories;
                        tables.push(...this.getConfigTables(agentConfig[agentConfigKey], section, idx));
                        let diffOpts = [];
                        Object.keys(section.opts).forEach(x => {
                          diffOpts.push(x);
                        });
                        const columns = ['', ...diffOpts.filter(x => x !== 'check_all' && x !== 'check_sum')];
                        let rows = [];
                        directories.forEach(x => {
                          let row = [];
                          row.push(x.dir);
                          columns.forEach(y => {
                            if (y !== '') {
                              row.push(x.opts.indexOf(y) > -1 ? 'yes' : 'no');
                            }
                          });
                          row.push(x.recursion_level);
                          rows.push(row);
                        });
                        columns.forEach((x, idx) => {
                          columns[idx] = section.opts[x];
                        });
                        columns.push('RL');
                        tables.push({
                          title: 'Monitored directories',
                          type: 'table',
                          columns,
                          rows
                        });
                      } else {
                        tables.push(...this.getConfigTables(agentConfig[agentConfigKey], section, idx));
                      }
                    }
                  }
                } else {
                  // Print no configured module and link to the documentation
                  printer.addContent({
                    text: ['This module is not configured. Please take a look on how to configure it in ', {
                      text: `${section.subtitle.toLowerCase()} configuration.`,
                      link: section.docuLink,
                      style: {
                        fontSize: 12,
                        color: '#1a0dab'
                      }
                    }],
                    margin: [0, 0, 0, 20]
                  });
                }
              } catch (error) {
                (0, _logger.log)('reporting:report', error.message || error, 'debug');
              }

              idx++;
            }

            for (const table of tables) {
              printer.addConfigTables([table]);
            }
          }

          idxComponent++;
          tables = [];
        }
      }

      await printer.print(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID, name));
      return response.ok({
        body: {
          success: true,
          message: `Report ${name} was created`
        }
      });
    } catch (error) {
      (0, _logger.log)('reporting:createReportsAgents', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
    }
  }
  /**
   * Create a report for the agents
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {*} reports list or ErrorResponse
   */


  async createReportsAgentsInventory(context, request, response) {
    try {
      (0, _logger.log)('reporting:createReportsAgentsInventory', `Report started`, 'info');
      const {
        browserTimezone,
        searchBar,
        filters,
        time,
        name
      } = request.body;
      const {
        agentID
      } = request.params;
      const {
        id: apiId,
        pattern: indexPattern
      } = request.headers;
      const {
        from,
        to
      } = time || {}; // Init

      const printer = new _printer.ReportPrinter();
      const {
        username: userID
      } = await context.wazuh.security.getCurrentUser(request, context);
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID));
      (0, _logger.log)('reporting:createReportsAgentsInventory', `Syscollector report`, 'debug');
      const sanitizedFilters = filters ? this.sanitizeKibanaFilters(filters, searchBar) : false; // Get the agent OS

      let agentOs = '';

      try {
        const agentResponse = await context.wazuh.api.client.asCurrentUser.request('GET', '/agents', {
          params: {
            q: `id=${agentID}`
          }
        }, {
          apiHostID: apiId
        });
        agentOs = agentResponse.data.data.affected_items[0].os.platform;
      } catch (error) {
        (0, _logger.log)('reporting:createReportsAgentsInventory', error.message || error, 'debug');
      } // Add title


      printer.addContentWithNewLine({
        text: 'Inventory data report',
        style: 'h1'
      }); // Add table with the agent info

      await this.buildAgentsTable(context, printer, [agentID], apiId); // Get syscollector packages and processes

      const agentRequestsInventory = [{
        endpoint: `/syscollector/${agentID}/packages`,
        loggerMessage: `Fetching packages for agent ${agentID}`,
        table: {
          title: 'Packages',
          columns: agentOs === 'windows' ? [{
            id: 'name',
            label: 'Name'
          }, {
            id: 'architecture',
            label: 'Architecture'
          }, {
            id: 'version',
            label: 'Version'
          }, {
            id: 'vendor',
            label: 'Vendor'
          }] : [{
            id: 'name',
            label: 'Name'
          }, {
            id: 'architecture',
            label: 'Architecture'
          }, {
            id: 'version',
            label: 'Version'
          }, {
            id: 'vendor',
            label: 'Vendor'
          }, {
            id: 'description',
            label: 'Description'
          }]
        }
      }, {
        endpoint: `/syscollector/${agentID}/processes`,
        loggerMessage: `Fetching processes for agent ${agentID}`,
        table: {
          title: 'Processes',
          columns: agentOs === 'windows' ? [{
            id: 'name',
            label: 'Name'
          }, {
            id: 'cmd',
            label: 'CMD'
          }, {
            id: 'priority',
            label: 'Priority'
          }, {
            id: 'nlwp',
            label: 'NLWP'
          }] : [{
            id: 'name',
            label: 'Name'
          }, {
            id: 'euser',
            label: 'Effective user'
          }, {
            id: 'nice',
            label: 'Priority'
          }, {
            id: 'state',
            label: 'State'
          }]
        },
        mapResponseItems: item => agentOs === 'windows' ? item : { ...item,
          state: _processStateEquivalence.default[item.state]
        }
      }, {
        endpoint: `/syscollector/${agentID}/ports`,
        loggerMessage: `Fetching ports for agent ${agentID}`,
        table: {
          title: 'Network ports',
          columns: agentOs === 'windows' ? [{
            id: 'local_ip',
            label: 'Local IP'
          }, {
            id: 'local_port',
            label: 'Local port'
          }, {
            id: 'process',
            label: 'Process'
          }, {
            id: 'state',
            label: 'State'
          }, {
            id: 'protocol',
            label: 'Protocol'
          }] : [{
            id: 'local_ip',
            label: 'Local IP'
          }, {
            id: 'local_port',
            label: 'Local port'
          }, {
            id: 'state',
            label: 'State'
          }, {
            id: 'protocol',
            label: 'Protocol'
          }]
        },
        mapResponseItems: item => ({ ...item,
          local_ip: item.local.ip,
          local_port: item.local.port
        })
      }, {
        endpoint: `/syscollector/${agentID}/netiface`,
        loggerMessage: `Fetching netiface for agent ${agentID}`,
        table: {
          title: 'Network interfaces',
          columns: [{
            id: 'name',
            label: 'Name'
          }, {
            id: 'mac',
            label: 'Mac'
          }, {
            id: 'state',
            label: 'State'
          }, {
            id: 'mtu',
            label: 'MTU'
          }, {
            id: 'type',
            label: 'Type'
          }]
        }
      }, {
        endpoint: `/syscollector/${agentID}/netaddr`,
        loggerMessage: `Fetching netaddr for agent ${agentID}`,
        table: {
          title: 'Network settings',
          columns: [{
            id: 'iface',
            label: 'Interface'
          }, {
            id: 'address',
            label: 'address'
          }, {
            id: 'netmask',
            label: 'Netmask'
          }, {
            id: 'proto',
            label: 'Protocol'
          }, {
            id: 'broadcast',
            label: 'Broadcast'
          }]
        }
      }];
      agentOs === 'windows' && agentRequestsInventory.push({
        endpoint: `/syscollector/${agentID}/hotfixes`,
        loggerMessage: `Fetching hotfixes for agent ${agentID}`,
        table: {
          title: 'Windows updates',
          columns: [{
            id: 'hotfix',
            label: 'Update code'
          }]
        }
      });

      const requestInventory = async agentRequestInventory => {
        try {
          (0, _logger.log)('reporting:createReportsAgentsInventory', agentRequestInventory.loggerMessage, 'debug');
          const inventoryResponse = await context.wazuh.api.client.asCurrentUser.request('GET', agentRequestInventory.endpoint, {}, {
            apiHostID: apiId
          });
          const inventory = inventoryResponse && inventoryResponse.data && inventoryResponse.data.data && inventoryResponse.data.data.affected_items;

          if (inventory) {
            return { ...agentRequestInventory.table,
              items: agentRequestInventory.mapResponseItems ? inventory.map(agentRequestInventory.mapResponseItems) : inventory
            };
          }
        } catch (error) {
          (0, _logger.log)('reporting:createReportsAgentsInventory', error.message || error, 'debug');
        }
      };

      if (time) {
        await this.extendedInformation(context, printer, 'agents', 'syscollector', apiId, from, to, sanitizedFilters + ' AND rule.groups: "vulnerability-detector"', indexPattern, agentID);
      } // Add inventory tables


      (await Promise.all(agentRequestsInventory.map(requestInventory))).filter(table => table).forEach(table => printer.addSimpleTable(table)); // Print the document

      await printer.print(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID, name));
      return response.ok({
        body: {
          success: true,
          message: `Report ${name} was created`
        }
      });
    } catch (error) {
      (0, _logger.log)('reporting:createReportsAgents', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
    }
  }
  /**
   * Fetch the reports list
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Array<Object>} reports list or ErrorResponse
   */


  async getReports(context, request, response) {
    try {
      (0, _logger.log)('reporting:getReports', `Fetching created reports`, 'info');
      const {
        username: userID
      } = await context.wazuh.security.getCurrentUser(request, context);
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);

      const userReportsDirectory = _path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID);

      (0, _filesystem.createDirectoryIfNotExists)(userReportsDirectory);
      (0, _logger.log)('reporting:getReports', `Directory: ${userReportsDirectory}`, 'debug');

      const sortReportsByDate = (a, b) => a.date < b.date ? 1 : a.date > b.date ? -1 : 0;

      const reports = _fs.default.readdirSync(userReportsDirectory).map(file => {
        const stats = _fs.default.statSync(userReportsDirectory + '/' + file); // Get the file creation time (bithtime). It returns the first value that is a truthy value of next file stats: birthtime, mtime, ctime and atime.
        // This solves some OSs can have the bithtimeMs equal to 0 and returns the date like 1970-01-01


        const birthTimeField = ['birthtime', 'mtime', 'ctime', 'atime'].find(time => stats[`${time}Ms`]);
        return {
          name: file,
          size: stats.size,
          date: stats[birthTimeField]
        };
      });

      (0, _logger.log)('reporting:getReports', `Using TimSort for sorting ${reports.length} items`, 'debug');
      TimSort.sort(reports, sortReportsByDate);
      (0, _logger.log)('reporting:getReports', `Total reports: ${reports.length}`, 'debug');
      return response.ok({
        body: {
          reports
        }
      });
    } catch (error) {
      (0, _logger.log)('reporting:getReports', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5031, 500, response);
    }
  }
  /**
   * Fetch specific report
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} report or ErrorResponse
   */


  async getReportByName(context, request, response) {
    try {
      (0, _logger.log)('reporting:getReportByName', `Getting ${request.params.name} report`, 'debug');
      const {
        username: userID
      } = await context.wazuh.security.getCurrentUser(request, context);

      const reportFileBuffer = _fs.default.readFileSync(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID, request.params.name));

      return response.ok({
        headers: {
          'Content-Type': 'application/pdf'
        },
        body: reportFileBuffer
      });
    } catch (error) {
      (0, _logger.log)('reporting:getReportByName', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5030, 500, response);
    }
  }
  /**
   * Delete specific report
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async deleteReportByName(context, request, response) {
    try {
      (0, _logger.log)('reporting:deleteReportByName', `Deleting ${request.params.name} report`, 'debug');
      const {
        username: userID
      } = await context.wazuh.security.getCurrentUser(request, context);

      _fs.default.unlinkSync(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, userID, request.params.name));

      (0, _logger.log)('reporting:deleteReportByName', `${request.params.name} report was deleted`, 'info');
      return response.ok({
        body: {
          error: 0
        }
      });
    } catch (error) {
      (0, _logger.log)('reporting:deleteReportByName', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5032, 500, response);
    }
  }

}

exports.WazuhReportingCtrl = WazuhReportingCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLXJlcG9ydGluZy50cyJdLCJuYW1lcyI6WyJXYXp1aFJlcG9ydGluZ0N0cmwiLCJjb25zdHJ1Y3RvciIsInNhbml0aXplS2liYW5hRmlsdGVycyIsImZpbHRlcnMiLCJzZWFyY2hCYXIiLCJsZW5ndGgiLCJzdHIiLCJhZ2VudHNGaWx0ZXIiLCJmaWx0ZXIiLCJtZXRhIiwiY29udHJvbGxlZEJ5IiwiQVVUSE9SSVpFRF9BR0VOVFMiLCJwdXNoIiwibGVuIiwiaSIsIm5lZ2F0ZSIsImtleSIsInZhbHVlIiwicGFyYW1zIiwidHlwZSIsImd0ZSIsImx0IiwicXVlcnkiLCJhZ2VudHNGaWx0ZXJTdHIiLCJtYXAiLCJqb2luIiwicmVuZGVySGVhZGVyIiwiY29udGV4dCIsInByaW50ZXIiLCJzZWN0aW9uIiwidGFiIiwiaXNBZ2VudHMiLCJhcGlJZCIsImluY2x1ZGVzIiwiYWRkQ29udGVudCIsInRleHQiLCJXQVpVSF9NT0RVTEVTIiwidGl0bGUiLCJzdHlsZSIsImZvbnRTaXplIiwiY29sb3IiLCJtYXJnaW4iLCJPYmplY3QiLCJrZXlzIiwiYWRkTmV3TGluZSIsImJ1aWxkQWdlbnRzVGFibGUiLCJhZ2VudFJlc3BvbnNlIiwid2F6dWgiLCJhcGkiLCJjbGllbnQiLCJhc0N1cnJlbnRVc2VyIiwicmVxdWVzdCIsImFnZW50c19saXN0IiwiYXBpSG9zdElEIiwiYWdlbnREYXRhIiwiZGF0YSIsImFmZmVjdGVkX2l0ZW1zIiwic3RhdHVzIiwiYWRkQ29udGVudFdpdGhOZXdMaW5lIiwidG9Mb3dlckNhc2UiLCJncm91cCIsImFnZW50R3JvdXBzIiwiZGVzY3JpcHRpb24iLCJlcnJvciIsIm1lc3NhZ2UiLCJQcm9taXNlIiwicmVqZWN0IiwiYWdlbnRJRHMiLCJtdWx0aSIsImFnZW50Um93cyIsImFnZW50c1Jlc3BvbnNlIiwiYWdlbnRzRGF0YSIsImFnZW50IiwibWFuYWdlciIsIm1hbmFnZXJfaG9zdCIsIm9zIiwibmFtZSIsInZlcnNpb24iLCJhZ2VudElEIiwicSIsImFkZFNpbXBsZVRhYmxlIiwiY29sdW1ucyIsImlkIiwibGFiZWwiLCJpdGVtcyIsImV4dGVuZGVkSW5mb3JtYXRpb24iLCJmcm9tIiwidG8iLCJwYXR0ZXJuIiwiV0FaVUhfQUxFUlRTX1BBVFRFUk4iLCJFcnJvciIsImFnZW50cyIsImxpbWl0IiwidG90YWxBZ2VudHMiLCJ0b3RhbF9hZmZlY3RlZF9pdGVtcyIsInZ1bG5lcmFiaWxpdGllc0xldmVscyIsInZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0NvdW50IiwiYWxsIiwidnVsbmVyYWJpbGl0aWVzTGV2ZWwiLCJjb3VudCIsIlZ1bG5lcmFiaWxpdHlSZXF1ZXN0IiwidW5pcXVlU2V2ZXJpdHlDb3VudCIsInRvTG9jYWxlTG93ZXJDYXNlIiwidW5kZWZpbmVkIiwidnVsbmVyYWJpbGl0aWVzUmVzcG9uc2UiLCJhZGRMaXN0IiwibGlzdCIsImxvd1JhbmsiLCJ0b3BBZ2VudENvdW50IiwibWVkaXVtUmFuayIsImhpZ2hSYW5rIiwiY3JpdGljYWxSYW5rIiwiY3ZlUmFuayIsInRvcENWRUNvdW50IiwiaXRlbSIsInRvcCIsImluZGV4T2YiLCJjdmUiLCJsZXZlbDE1UmFuayIsIk92ZXJ2aWV3UmVxdWVzdCIsInRvcExldmVsMTUiLCJ0b3A1Um9vdGtpdHNSYW5rIiwiUm9vdGNoZWNrUmVxdWVzdCIsInRvcDVSb290a2l0c0RldGVjdGVkIiwiaGlkZGVuUGlkcyIsImFnZW50c1dpdGhIaWRkZW5QaWRzIiwiaGlkZGVuUG9ydHMiLCJhZ2VudHNXaXRoSGlkZGVuUG9ydHMiLCJ0b3BQY2lSZXF1aXJlbWVudHMiLCJQQ0lSZXF1ZXN0IiwidG9wUENJUmVxdWlyZW1lbnRzIiwicnVsZXMiLCJnZXRSdWxlc0J5UmVxdWlyZW1lbnQiLCJQQ0kiLCJjb250ZW50IiwidG9wVFNDUmVxdWlyZW1lbnRzIiwiVFNDUmVxdWVzdCIsIlRTQyIsInRvcEdkcHJSZXF1aXJlbWVudHMiLCJHRFBSUmVxdWVzdCIsInRvcEdEUFJSZXF1aXJlbWVudHMiLCJHRFBSIiwiYXVkaXRBZ2VudHNOb25TdWNjZXNzIiwiQXVkaXRSZXF1ZXN0IiwiZ2V0VG9wM0FnZW50c1N1ZG9Ob25TdWNjZXNzZnVsIiwiYXVkaXRBZ2VudHNGYWlsZWRTeXNjYWxsIiwiZ2V0VG9wM0FnZW50c0ZhaWxlZFN5c2NhbGxzIiwic3lzY2FsbF9pZCIsInN5c2NhbGwiLCJzeXNjYWxsX3N5c2NhbGwiLCJTeXNjaGVja1JlcXVlc3QiLCJ0b3AzUnVsZXMiLCJ0b3AzYWdlbnRzIiwiYXVkaXRGYWlsZWRTeXNjYWxsIiwiZ2V0VG9wRmFpbGVkU3lzY2FsbHMiLCJsYXN0U2NhblJlc3BvbnNlIiwibGFzdFNjYW5EYXRhIiwic3RhcnQiLCJlbmQiLCJsYXN0VGVuRGVsZXRlZCIsImxhc3RUZW5EZWxldGVkRmlsZXMiLCJsYXN0VGVuTW9kaWZpZWQiLCJsYXN0VGVuTW9kaWZpZWRGaWxlcyIsInJlcXVlc3RzU3lzY29sbGVjdG9yTGlzdHMiLCJlbmRwb2ludCIsImxvZ2dlck1lc3NhZ2UiLCJtYXBSZXNwb25zZSIsImhhcmR3YXJlIiwiY3B1IiwiY29yZXMiLCJyYW0iLCJ0b3RhbCIsIk51bWJlciIsInRvRml4ZWQiLCJvc0RhdGEiLCJzeXNuYW1lIiwiYXJjaGl0ZWN0dXJlIiwicmVsZWFzZSIsInN5c2NvbGxlY3Rvckxpc3RzIiwicmVxdWVzdFN5c2NvbGxlY3RvciIsInJlc3BvbnNlU3lzY29sbGVjdG9yIiwic3lzY29sbGVjdG9yTGlzdCIsImZvckVhY2giLCJ2dWxuZXJhYmlsaXRpZXNSZXF1ZXN0cyIsInZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0l0ZW1zIiwidG9wUGFja2FnZXMiLCJmbGF0IiwidG9wQ3JpdGljYWxQYWNrYWdlcyIsInRvcFBhY2thZ2VzV2l0aENWRSIsImN1c3RvbXVsIiwiY3JpdGljYWwiLCJwYWNrYWdlIiwidWwiLCJyZWZlcmVuY2VzIiwic3Vic3RyaW5nIiwibGluayIsInRvcEhpZ2hQYWNrYWdlcyIsImdldENvbmZpZ1Jvd3MiLCJsYWJlbHMiLCJyZXN1bHQiLCJwcm9wIiwiQXJyYXkiLCJpc0FycmF5IiwieCIsImlkeCIsIkpTT04iLCJzdHJpbmdpZnkiLCJLZXlFcXVpdmFsZW5jZSIsImdldENvbmZpZ1RhYmxlcyIsImFycmF5IiwicGxhaW5EYXRhIiwibmVzdGVkRGF0YSIsInRhYmxlRGF0YSIsImNvbmZpZyIsImNvbmZpZ3VyYXRpb24iLCJpc0dyb3VwQ29uZmlnIiwib3B0aW9ucyIsImhpZGVIZWFkZXIiLCJ0YWJzIiwicm93cyIsImNvbCIsInRvVXBwZXJDYXNlIiwic2xpY2UiLCJyb3ciLCJuZXN0IiwiY3JlYXRlUmVwb3J0c01vZHVsZXMiLCJyZXNwb25zZSIsImJyb3dzZXJUaW1lem9uZSIsInRpbWUiLCJ0YWJsZXMiLCJib2R5IiwibW9kdWxlSUQiLCJpbmRleFBhdHRlcm4iLCJoZWFkZXJzIiwiUmVwb3J0UHJpbnRlciIsInVzZXJuYW1lIiwidXNlcklEIiwic2VjdXJpdHkiLCJnZXRDdXJyZW50VXNlciIsIldBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIIiwiV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCIsInBhdGgiLCJzYW5pdGl6ZWRGaWx0ZXJzIiwiYWRkVGltZVJhbmdlQW5kRmlsdGVycyIsIkRhdGUiLCJnZXRUaW1lIiwiYWRkVmlzdWFsaXphdGlvbnMiLCJhZGRUYWJsZXMiLCJhZGRBZ2VudHNGaWx0ZXJzIiwicHJpbnQiLCJvayIsInN1Y2Nlc3MiLCJjcmVhdGVSZXBvcnRzR3JvdXBzIiwiY29tcG9uZW50cyIsImdyb3VwSUQiLCJlcXVpdmFsZW5jZXMiLCJsb2NhbGZpbGUiLCJvc3F1ZXJ5IiwiY29tbWFuZCIsInN5c2NoZWNrIiwic3lzY29sbGVjdG9yIiwicm9vdGNoZWNrIiwic2NhIiwiY29uZmlndXJhdGlvblJlc3BvbnNlIiwiZmlsdGVyVGl0bGUiLCJpbmRleCIsImNvbmNhdCIsIl9kIiwiYyIsIkFnZW50Q29uZmlndXJhdGlvbiIsImNvbmZpZ3VyYXRpb25zIiwicyIsInNlY3Rpb25zIiwib3B0cyIsImNuIiwid28iLCJ3b2RsZSIsImdyb3VwcyIsIm9iaiIsImxvZ2Zvcm1hdCIsInNhdmVpZHgiLCJfZDIiLCJkaXJlY3RvcmllcyIsImRpZmZPcHRzIiwieSIsInJlY3Vyc2lvbl9sZXZlbCIsInRhYmxlIiwiYWRkQ29uZmlnVGFibGVzIiwiYWdlbnRzSW5Hcm91cCIsImFnZW50c0luR3JvdXBSZXNwb25zZSIsImNyZWF0ZVJlcG9ydHNBZ2VudHMiLCJ3bW9kdWxlc1Jlc3BvbnNlIiwiaWR4Q29tcG9uZW50IiwidGl0bGVPZlNlY3Rpb24iLCJjb25maWdzIiwiY29uZiIsImFnZW50Q29uZmlnUmVzcG9uc2UiLCJjb21wb25lbnQiLCJhZ2VudENvbmZpZyIsInN1YnRpdGxlIiwiZGVzYyIsImFnZW50Q29uZmlnS2V5IiwiZmlsdGVyQnkiLCJtYXRyaXgiLCJkaXIiLCJkb2N1TGluayIsImNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnkiLCJhZ2VudE9zIiwicGxhdGZvcm0iLCJhZ2VudFJlcXVlc3RzSW52ZW50b3J5IiwibWFwUmVzcG9uc2VJdGVtcyIsInN0YXRlIiwiUHJvY2Vzc0VxdWl2YWxlbmNlIiwibG9jYWxfaXAiLCJsb2NhbCIsImlwIiwibG9jYWxfcG9ydCIsInBvcnQiLCJyZXF1ZXN0SW52ZW50b3J5IiwiYWdlbnRSZXF1ZXN0SW52ZW50b3J5IiwiaW52ZW50b3J5UmVzcG9uc2UiLCJpbnZlbnRvcnkiLCJnZXRSZXBvcnRzIiwidXNlclJlcG9ydHNEaXJlY3RvcnkiLCJzb3J0UmVwb3J0c0J5RGF0ZSIsImEiLCJiIiwiZGF0ZSIsInJlcG9ydHMiLCJmcyIsInJlYWRkaXJTeW5jIiwiZmlsZSIsInN0YXRzIiwic3RhdFN5bmMiLCJiaXJ0aFRpbWVGaWVsZCIsImZpbmQiLCJzaXplIiwiVGltU29ydCIsInNvcnQiLCJnZXRSZXBvcnRCeU5hbWUiLCJyZXBvcnRGaWxlQnVmZmVyIiwicmVhZEZpbGVTeW5jIiwiZGVsZXRlUmVwb3J0QnlOYW1lIiwidW5saW5rU3luYyJd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QUdjLFVBQUgsQ0FDRXRHLGNBQUt4TixJQUFMLENBQVV1TixzREFBVixFQUF1REosTUFBdkQsRUFBK0R6TCxPQUFPLENBQUNqQyxNQUFSLENBQWUwRCxJQUE5RSxDQURGOztBQUdBLHVCQUFJLDhCQUFKLEVBQXFDLEdBQUV6QixPQUFPLENBQUNqQyxNQUFSLENBQWUwRCxJQUFLLHFCQUEzRCxFQUFpRixNQUFqRjtBQUNBLGFBQU9zSixRQUFRLENBQUN3QixFQUFULENBQVk7QUFDakJwQixRQUFBQSxJQUFJLEVBQUU7QUFBRXZLLFVBQUFBLEtBQUssRUFBRTtBQUFUO0FBRFcsT0FBWixDQUFQO0FBR0QsS0FWRCxDQVVFLE9BQU9BLEtBQVAsRUFBYztBQUNkLHVCQUFJLDhCQUFKLEVBQW9DQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQXJEO0FBQ0EsYUFBTyxrQ0FBY0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUEvQixFQUFzQyxJQUF0QyxFQUE0QyxHQUE1QyxFQUFpRG1LLFFBQWpELENBQVA7QUFDRDtBQUNGOztBQWwrRDZCIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIENsYXNzIGZvciBXYXp1aCByZXBvcnRpbmcgY29udHJvbGxlclxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjEgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmltcG9ydCBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IGZzIGZyb20gJ2ZzJztcbmltcG9ydCB7IFdBWlVIX01PRFVMRVMgfSBmcm9tICcuLi8uLi9jb21tb24vd2F6dWgtbW9kdWxlcyc7XG5pbXBvcnQgKiBhcyBUaW1Tb3J0IGZyb20gJ3RpbXNvcnQnO1xuaW1wb3J0IHsgRXJyb3JSZXNwb25zZSB9IGZyb20gJy4uL2xpYi9lcnJvci1yZXNwb25zZSc7XG5pbXBvcnQgKiBhcyBWdWxuZXJhYmlsaXR5UmVxdWVzdCBmcm9tICcuLi9saWIvcmVwb3J0aW5nL3Z1bG5lcmFiaWxpdHktcmVxdWVzdCc7XG5pbXBvcnQgKiBhcyBPdmVydmlld1JlcXVlc3QgZnJvbSAnLi4vbGliL3JlcG9ydGluZy9vdmVydmlldy1yZXF1ZXN0JztcbmltcG9ydCAqIGFzIFJvb3RjaGVja1JlcXVlc3QgZnJvbSAnLi4vbGliL3JlcG9ydGluZy9yb290Y2hlY2stcmVxdWVzdCc7XG5pbXBvcnQgKiBhcyBQQ0lSZXF1ZXN0IGZyb20gJy4uL2xpYi9yZXBvcnRpbmcvcGNpLXJlcXVlc3QnO1xuaW1wb3J0ICogYXMgR0RQUlJlcXVlc3QgZnJvbSAnLi4vbGliL3JlcG9ydGluZy9nZHByLXJlcXVlc3QnO1xuaW1wb3J0ICogYXMgVFNDUmVxdWVzdCBmcm9tICcuLi9saWIvcmVwb3J0aW5nL3RzYy1yZXF1ZXN0JztcbmltcG9ydCAqIGFzIEF1ZGl0UmVxdWVzdCBmcm9tICcuLi9saWIvcmVwb3J0aW5nL2F1ZGl0LXJlcXVlc3QnO1xuaW1wb3J0ICogYXMgU3lzY2hlY2tSZXF1ZXN0IGZyb20gJy4uL2xpYi9yZXBvcnRpbmcvc3lzY2hlY2stcmVxdWVzdCc7XG5pbXBvcnQgUENJIGZyb20gJy4uL2ludGVncmF0aW9uLWZpbGVzL3BjaS1yZXF1aXJlbWVudHMtcGRmbWFrZSc7XG5pbXBvcnQgR0RQUiBmcm9tICcuLi9pbnRlZ3JhdGlvbi1maWxlcy9nZHByLXJlcXVpcmVtZW50cy1wZGZtYWtlJztcbmltcG9ydCBUU0MgZnJvbSAnLi4vaW50ZWdyYXRpb24tZmlsZXMvdHNjLXJlcXVpcmVtZW50cy1wZGZtYWtlJztcbmltcG9ydCBQcm9jZXNzRXF1aXZhbGVuY2UgZnJvbSAnLi4vbGliL3Byb2Nlc3Mtc3RhdGUtZXF1aXZhbGVuY2UnO1xuaW1wb3J0IHsgS2V5RXF1aXZhbGVuY2UgfSBmcm9tICcuLi8uLi9jb21tb24vY3N2LWtleS1lcXVpdmFsZW5jZSc7XG5pbXBvcnQgeyBBZ2VudENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9saWIvcmVwb3J0aW5nL2FnZW50LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgS2liYW5hUmVxdWVzdCwgUmVxdWVzdEhhbmRsZXJDb250ZXh0LCBLaWJhbmFSZXNwb25zZUZhY3RvcnkgfSBmcm9tICdzcmMvY29yZS9zZXJ2ZXInO1xuaW1wb3J0IHsgUmVwb3J0UHJpbnRlciB9IGZyb20gJy4uL2xpYi9yZXBvcnRpbmcvcHJpbnRlcic7XG5cbmltcG9ydCB7IGxvZyB9IGZyb20gJy4uL2xpYi9sb2dnZXInO1xuaW1wb3J0IHtcbiAgV0FaVUhfQUxFUlRTX1BBVFRFUk4sXG4gIFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRILFxuICBXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILFxuICBBVVRIT1JJWkVEX0FHRU5UUyxcbn0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cywgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzIH0gZnJvbSAnLi4vbGliL2ZpbGVzeXN0ZW0nO1xuXG5leHBvcnQgY2xhc3MgV2F6dWhSZXBvcnRpbmdDdHJsIHtcbiAgY29uc3RydWN0b3IoKSB7fVxuXG4gIC8qKlxuICAgKiBUaGlzIGRvIGZvcm1hdCB0byBmaWx0ZXJzXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBmaWx0ZXJzIEUuZzogY2x1c3Rlci5uYW1lOiB3YXp1aCBBTkQgcnVsZS5ncm91cHM6IHZ1bG5lcmFiaWxpdHlcbiAgICogQHBhcmFtIHtTdHJpbmd9IHNlYXJjaEJhciBzZWFyY2ggdGVybVxuICAgKi9cbiAgcHJpdmF0ZSBzYW5pdGl6ZUtpYmFuYUZpbHRlcnMoZmlsdGVyczogYW55LCBzZWFyY2hCYXI/OiBzdHJpbmcpOiBbc3RyaW5nLCBzdHJpbmddIHtcbiAgICBsb2coJ3JlcG9ydGluZzpzYW5pdGl6ZUtpYmFuYUZpbHRlcnMnLCBgU3RhcnRlZCB0byBzYW5pdGl6ZSBmaWx0ZXJzYCwgJ2luZm8nKTtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnNhbml0aXplS2liYW5hRmlsdGVycycsXG4gICAgICBgZmlsdGVyczogJHtmaWx0ZXJzLmxlbmd0aH0sIHNlYXJjaEJhcjogJHtzZWFyY2hCYXJ9YCxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICAgIGxldCBzdHIgPSAnJztcblxuICAgIGNvbnN0IGFnZW50c0ZpbHRlcjogYW55ID0gW107XG5cbiAgICAvL3NlcGFyYXRlIGFnZW50cyBmaWx0ZXJcbiAgICBmaWx0ZXJzID0gZmlsdGVycy5maWx0ZXIoKGZpbHRlcikgPT4ge1xuICAgICAgaWYgKGZpbHRlci5tZXRhLmNvbnRyb2xsZWRCeSA9PT0gQVVUSE9SSVpFRF9BR0VOVFMpIHtcbiAgICAgICAgYWdlbnRzRmlsdGVyLnB1c2goZmlsdGVyKTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGZpbHRlcjtcbiAgICB9KTtcblxuICAgIGNvbnN0IGxlbiA9IGZpbHRlcnMubGVuZ3RoO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsZW47IGkrKykge1xuICAgICAgY29uc3QgeyBuZWdhdGUsIGtleSwgdmFsdWUsIHBhcmFtcywgdHlwZSB9ID0gZmlsdGVyc1tpXS5tZXRhO1xuICAgICAgc3RyICs9IGAke25lZ2F0ZSA/ICdOT1QgJyA6ICcnfWA7XG4gICAgICBzdHIgKz0gYCR7a2V5fTogYDtcbiAgICAgIHN0ciArPSBgJHtcbiAgICAgICAgdHlwZSA9PT0gJ3JhbmdlJyA/IGAke3BhcmFtcy5ndGV9LSR7cGFyYW1zLmx0fWAgOiAhIXZhbHVlID8gdmFsdWUgOiAocGFyYW1zIHx8IHt9KS5xdWVyeVxuICAgICAgfWA7XG4gICAgICBzdHIgKz0gYCR7aSA9PT0gbGVuIC0gMSA/ICcnIDogJyBBTkQgJ31gO1xuICAgIH1cblxuICAgIGlmIChzZWFyY2hCYXIpIHtcbiAgICAgIHN0ciArPSAnIEFORCAnICsgc2VhcmNoQmFyO1xuICAgIH1cblxuICAgIGNvbnN0IGFnZW50c0ZpbHRlclN0ciA9IGFnZW50c0ZpbHRlci5tYXAoKGZpbHRlcikgPT4gZmlsdGVyLm1ldGEudmFsdWUpLmpvaW4oJywnKTtcblxuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6c2FuaXRpemVLaWJhbmFGaWx0ZXJzJyxcbiAgICAgIGBzdHI6ICR7c3RyfSwgYWdlbnRzRmlsdGVyU3RyOiAke2FnZW50c0ZpbHRlclN0cn1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICByZXR1cm4gW3N0ciwgYWdlbnRzRmlsdGVyU3RyXTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHBlcmZvcm1zIHRoZSByZW5kZXJpbmcgb2YgZ2l2ZW4gaGVhZGVyXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBwcmludGVyIHNlY3Rpb24gdGFyZ2V0XG4gICAqIEBwYXJhbSB7U3RyaW5nfSBzZWN0aW9uIHNlY3Rpb24gdGFyZ2V0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSB0YWIgdGFiIHRhcmdldFxuICAgKiBAcGFyYW0ge0Jvb2xlYW59IGlzQWdlbnRzIGlzIGFnZW50cyBzZWN0aW9uXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBhcGlJZCBJRCBvZiBBUElcbiAgICovXG4gIHByaXZhdGUgYXN5bmMgcmVuZGVySGVhZGVyKGNvbnRleHQsIHByaW50ZXIsIHNlY3Rpb24sIHRhYiwgaXNBZ2VudHMsIGFwaUlkKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3JlcG9ydGluZzpyZW5kZXJIZWFkZXInLFxuICAgICAgICBgc2VjdGlvbjogJHtzZWN0aW9ufSwgdGFiOiAke3RhYn0sIGlzQWdlbnRzOiAke2lzQWdlbnRzfSwgYXBpSWQ6ICR7YXBpSWR9YCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIGlmIChzZWN0aW9uICYmIHR5cGVvZiBzZWN0aW9uID09PSAnc3RyaW5nJykge1xuICAgICAgICBpZiAoIVsnYWdlbnRDb25maWcnLCAnZ3JvdXBDb25maWcnXS5pbmNsdWRlcyhzZWN0aW9uKSkge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICB0ZXh0OiBXQVpVSF9NT0RVTEVTW3RhYl0udGl0bGUgKyAnIHJlcG9ydCcsXG4gICAgICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIGlmIChzZWN0aW9uID09PSAnYWdlbnRDb25maWcnKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6IGBBZ2VudCAke2lzQWdlbnRzfSBjb25maWd1cmF0aW9uYCxcbiAgICAgICAgICAgIHN0eWxlOiAnaDEnLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2UgaWYgKHNlY3Rpb24gPT09ICdncm91cENvbmZpZycpIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0FnZW50cyBpbiBncm91cCcsXG4gICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMTQsIGNvbG9yOiAnIzAwMCcgfSxcbiAgICAgICAgICAgIG1hcmdpbjogWzAsIDIwLCAwLCAwXSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBpZiAoc2VjdGlvbiA9PT0gJ2dyb3VwQ29uZmlnJyAmJiAhT2JqZWN0LmtleXMoaXNBZ2VudHMpLmxlbmd0aCkge1xuICAgICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgICAgdGV4dDogJ1RoZXJlIGFyZSBzdGlsbCBubyBhZ2VudHMgaW4gdGhpcyBncm91cC4nLFxuICAgICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMTIsIGNvbG9yOiAnIzAwMCcgfSxcbiAgICAgICAgICAgICAgbWFyZ2luOiBbMCwgMTAsIDAsIDBdLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHByaW50ZXIuYWRkTmV3TGluZSgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoaXNBZ2VudHMgJiYgdHlwZW9mIGlzQWdlbnRzID09PSAnb2JqZWN0Jykge1xuICAgICAgICBhd2FpdCB0aGlzLmJ1aWxkQWdlbnRzVGFibGUoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBwcmludGVyLFxuICAgICAgICAgIGlzQWdlbnRzLFxuICAgICAgICAgIGFwaUlkLFxuICAgICAgICAgIHNlY3Rpb24gPT09ICdncm91cENvbmZpZycgPyB0YWIgOiBmYWxzZVxuICAgICAgICApO1xuICAgICAgfVxuXG4gICAgICBpZiAoaXNBZ2VudHMgJiYgdHlwZW9mIGlzQWdlbnRzID09PSAnc3RyaW5nJykge1xuICAgICAgICBjb25zdCBhZ2VudFJlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICBgL2FnZW50c2AsXG4gICAgICAgICAgeyBwYXJhbXM6IHsgYWdlbnRzX2xpc3Q6IGlzQWdlbnRzIH0gfSxcbiAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICApO1xuICAgICAgICBjb25zdCBhZ2VudERhdGEgPSBhZ2VudFJlc3BvbnNlLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXTtcbiAgICAgICAgaWYgKGFnZW50RGF0YSAmJiBhZ2VudERhdGEuc3RhdHVzICE9PSAnYWN0aXZlJykge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICAgIHRleHQ6IGBXYXJuaW5nLiBBZ2VudCBpcyAke2FnZW50RGF0YS5zdGF0dXMudG9Mb3dlckNhc2UoKX1gLFxuICAgICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgYXdhaXQgdGhpcy5idWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIFtpc0FnZW50c10sIGFwaUlkKTtcblxuICAgICAgICBpZiAoYWdlbnREYXRhICYmIGFnZW50RGF0YS5ncm91cCkge1xuICAgICAgICAgIGNvbnN0IGFnZW50R3JvdXBzID0gYWdlbnREYXRhLmdyb3VwLmpvaW4oJywgJyk7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDogYEdyb3VwJHthZ2VudERhdGEuZ3JvdXAubGVuZ3RoID4gMSA/ICdzJyA6ICcnfTogJHthZ2VudEdyb3Vwc31gLFxuICAgICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmIChXQVpVSF9NT0RVTEVTW3RhYl0gJiYgV0FaVUhfTU9EVUxFU1t0YWJdLmRlc2NyaXB0aW9uKSB7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICB0ZXh0OiBXQVpVSF9NT0RVTEVTW3RhYl0uZGVzY3JpcHRpb24sXG4gICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgIH0pO1xuICAgICAgfVxuXG4gICAgICByZXR1cm47XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOnJlbmRlckhlYWRlcicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBidWlsZCB0aGUgYWdlbnRzIHRhYmxlXG4gICAqIEBwYXJhbSB7QXJyYXk8U3RyaW5ncz59IGlkcyBpZHMgb2YgYWdlbnRzXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBhcGlJZCBBUEkgaWRcbiAgICovXG4gIHByaXZhdGUgYXN5bmMgYnVpbGRBZ2VudHNUYWJsZShcbiAgICBjb250ZXh0LFxuICAgIHByaW50ZXI6IFJlcG9ydFByaW50ZXIsXG4gICAgYWdlbnRJRHM6IHN0cmluZ1tdLFxuICAgIGFwaUlkOiBzdHJpbmcsXG4gICAgbXVsdGkgPSBmYWxzZVxuICApIHtcbiAgICBpZiAoIWFnZW50SURzIHx8ICFhZ2VudElEcy5sZW5ndGgpIHJldHVybjtcbiAgICBsb2coJ3JlcG9ydGluZzpidWlsZEFnZW50c1RhYmxlJywgYCR7YWdlbnRJRHMubGVuZ3RofSBhZ2VudHMgZm9yIEFQSSAke2FwaUlkfWAsICdpbmZvJyk7XG4gICAgdHJ5IHtcbiAgICAgIGxldCBhZ2VudFJvd3MgPSBbXTtcbiAgICAgIGlmIChtdWx0aSkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGNvbnN0IGFnZW50c1Jlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgYC9ncm91cHMvJHttdWx0aX0vYWdlbnRzYCxcbiAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgeyBhcGlIb3N0SUQ6IGFwaUlkIH1cbiAgICAgICAgICApO1xuICAgICAgICAgIGNvbnN0IGFnZW50c0RhdGEgPVxuICAgICAgICAgICAgYWdlbnRzUmVzcG9uc2UgJiZcbiAgICAgICAgICAgIGFnZW50c1Jlc3BvbnNlLmRhdGEgJiZcbiAgICAgICAgICAgIGFnZW50c1Jlc3BvbnNlLmRhdGEuZGF0YSAmJlxuICAgICAgICAgICAgYWdlbnRzUmVzcG9uc2UuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zO1xuICAgICAgICAgIGFnZW50Um93cyA9IChhZ2VudHNEYXRhIHx8IFtdKS5tYXAoKGFnZW50KSA9PiAoe1xuICAgICAgICAgICAgLi4uYWdlbnQsXG4gICAgICAgICAgICBtYW5hZ2VyOiBhZ2VudC5tYW5hZ2VyIHx8IGFnZW50Lm1hbmFnZXJfaG9zdCxcbiAgICAgICAgICAgIG9zOlxuICAgICAgICAgICAgICBhZ2VudC5vcyAmJiBhZ2VudC5vcy5uYW1lICYmIGFnZW50Lm9zLnZlcnNpb25cbiAgICAgICAgICAgICAgICA/IGAke2FnZW50Lm9zLm5hbWV9ICR7YWdlbnQub3MudmVyc2lvbn1gXG4gICAgICAgICAgICAgICAgOiAnJyxcbiAgICAgICAgICB9KSk7XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgbG9nKFxuICAgICAgICAgICAgJ3JlcG9ydGluZzpidWlsZEFnZW50c1RhYmxlJyxcbiAgICAgICAgICAgIGBTa2lwIGFnZW50IGR1ZSB0bzogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWAsXG4gICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZm9yIChjb25zdCBhZ2VudElEIG9mIGFnZW50SURzKSB7XG4gICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGNvbnN0IGFnZW50UmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgICAgYC9hZ2VudHNgLFxuICAgICAgICAgICAgICB7IHBhcmFtczogeyBxOiBgaWQ9JHthZ2VudElEfWAgfSB9LFxuICAgICAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIGNvbnN0IFthZ2VudF0gPSBhZ2VudFJlc3BvbnNlLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtcztcbiAgICAgICAgICAgIGFnZW50Um93cy5wdXNoKHtcbiAgICAgICAgICAgICAgLi4uYWdlbnQsXG4gICAgICAgICAgICAgIG1hbmFnZXI6IGFnZW50Lm1hbmFnZXIgfHwgYWdlbnQubWFuYWdlcl9ob3N0LFxuICAgICAgICAgICAgICBvczpcbiAgICAgICAgICAgICAgICBhZ2VudC5vcyAmJiBhZ2VudC5vcy5uYW1lICYmIGFnZW50Lm9zLnZlcnNpb25cbiAgICAgICAgICAgICAgICAgID8gYCR7YWdlbnQub3MubmFtZX0gJHthZ2VudC5vcy52ZXJzaW9ufWBcbiAgICAgICAgICAgICAgICAgIDogJycsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgbG9nKFxuICAgICAgICAgICAgICAncmVwb3J0aW5nOmJ1aWxkQWdlbnRzVGFibGUnLFxuICAgICAgICAgICAgICBgU2tpcCBhZ2VudCBkdWUgdG86ICR7ZXJyb3IubWVzc2FnZSB8fCBlcnJvcn1gLFxuICAgICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICB7IGlkOiAnaWQnLCBsYWJlbDogJ0lEJyB9LFxuICAgICAgICAgIHsgaWQ6ICduYW1lJywgbGFiZWw6ICdOYW1lJyB9LFxuICAgICAgICAgIHsgaWQ6ICdpcCcsIGxhYmVsOiAnSVAnIH0sXG4gICAgICAgICAgeyBpZDogJ3ZlcnNpb24nLCBsYWJlbDogJ1ZlcnNpb24nIH0sXG4gICAgICAgICAgeyBpZDogJ21hbmFnZXInLCBsYWJlbDogJ01hbmFnZXInIH0sXG4gICAgICAgICAgeyBpZDogJ29zJywgbGFiZWw6ICdPUycgfSxcbiAgICAgICAgICB7IGlkOiAnZGF0ZUFkZCcsIGxhYmVsOiAnUmVnaXN0cmF0aW9uIGRhdGUnIH0sXG4gICAgICAgICAgeyBpZDogJ2xhc3RLZWVwQWxpdmUnLCBsYWJlbDogJ0xhc3Qga2VlcCBhbGl2ZScgfSxcbiAgICAgICAgXSxcbiAgICAgICAgaXRlbXM6IGFnZW50Um93cyxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpidWlsZEFnZW50c1RhYmxlJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGxvYWQgbW9yZSBpbmZvcm1hdGlvblxuICAgKiBAcGFyYW0geyp9IGNvbnRleHQgRW5kcG9pbnQgY29udGV4dFxuICAgKiBAcGFyYW0geyp9IHByaW50ZXIgcHJpbnRlciBpbnN0YW5jZVxuICAgKiBAcGFyYW0ge1N0cmluZ30gc2VjdGlvbiBzZWN0aW9uIHRhcmdldFxuICAgKiBAcGFyYW0ge09iamVjdH0gdGFiIHRhYiB0YXJnZXRcbiAgICogQHBhcmFtIHtTdHJpbmd9IGFwaUlkIElEIG9mIEFQSVxuICAgKiBAcGFyYW0ge051bWJlcn0gZnJvbSBUaW1lc3RhbXAgKG1zKSBmcm9tXG4gICAqIEBwYXJhbSB7TnVtYmVyfSB0byBUaW1lc3RhbXAgKG1zKSB0b1xuICAgKiBAcGFyYW0ge1N0cmluZ30gZmlsdGVycyBFLmc6IGNsdXN0ZXIubmFtZTogd2F6dWggQU5EIHJ1bGUuZ3JvdXBzOiB2dWxuZXJhYmlsaXR5XG4gICAqIEBwYXJhbSB7U3RyaW5nfSBwYXR0ZXJuXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBhZ2VudCBhZ2VudCB0YXJnZXRcbiAgICogQHJldHVybnMge09iamVjdH0gRXh0ZW5kZWQgaW5mb3JtYXRpb25cbiAgICovXG4gIHByaXZhdGUgYXN5bmMgZXh0ZW5kZWRJbmZvcm1hdGlvbihcbiAgICBjb250ZXh0LFxuICAgIHByaW50ZXIsXG4gICAgc2VjdGlvbixcbiAgICB0YWIsXG4gICAgYXBpSWQsXG4gICAgZnJvbSxcbiAgICB0byxcbiAgICBmaWx0ZXJzLFxuICAgIHBhdHRlcm4gPSBXQVpVSF9BTEVSVFNfUEFUVEVSTixcbiAgICBhZ2VudCA9IG51bGxcbiAgKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJyxcbiAgICAgICAgYFNlY3Rpb24gJHtzZWN0aW9ufSBhbmQgdGFiICR7dGFifSwgQVBJIGlzICR7YXBpSWR9LiBGcm9tICR7ZnJvbX0gdG8gJHt0b30uIEZpbHRlcnMgJHtmaWx0ZXJzfS4gSW5kZXggcGF0dGVybiAke3BhdHRlcm59YCxcbiAgICAgICAgJ2luZm8nXG4gICAgICApO1xuICAgICAgaWYgKHNlY3Rpb24gPT09ICdhZ2VudHMnICYmICFhZ2VudCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1JlcG9ydGluZyBmb3Igc3BlY2lmaWMgYWdlbnQgbmVlZHMgYW4gYWdlbnQgSUQgaW4gb3JkZXIgdG8gd29yayBwcm9wZXJseScpO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBhZ2VudHMgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAnR0VUJyxcbiAgICAgICAgJy9hZ2VudHMnLFxuICAgICAgICB7IHBhcmFtczogeyBsaW1pdDogMSB9IH0sXG4gICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICApO1xuXG4gICAgICBjb25zdCB0b3RhbEFnZW50cyA9IGFnZW50cy5kYXRhLmRhdGEudG90YWxfYWZmZWN0ZWRfaXRlbXM7XG5cbiAgICAgIGlmIChzZWN0aW9uID09PSAnb3ZlcnZpZXcnICYmIHRhYiA9PT0gJ3Z1bHMnKSB7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLFxuICAgICAgICAgICdGZXRjaGluZyBvdmVydmlldyB2dWxuZXJhYmlsaXR5IGRldGVjdG9yIG1ldHJpY3MnLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgdnVsbmVyYWJpbGl0aWVzTGV2ZWxzID0gWydMb3cnLCAnTWVkaXVtJywgJ0hpZ2gnLCAnQ3JpdGljYWwnXTtcblxuICAgICAgICBjb25zdCB2dWxuZXJhYmlsaXRpZXNSZXNwb25zZXNDb3VudCA9IChcbiAgICAgICAgICBhd2FpdCBQcm9taXNlLmFsbChcbiAgICAgICAgICAgIHZ1bG5lcmFiaWxpdGllc0xldmVscy5tYXAoYXN5bmMgKHZ1bG5lcmFiaWxpdGllc0xldmVsKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgY291bnQgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC51bmlxdWVTZXZlcml0eUNvdW50KFxuICAgICAgICAgICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICAgICAgICAgIGZyb20sXG4gICAgICAgICAgICAgICAgICB0byxcbiAgICAgICAgICAgICAgICAgIHZ1bG5lcmFiaWxpdGllc0xldmVsLFxuICAgICAgICAgICAgICAgICAgZmlsdGVycyxcbiAgICAgICAgICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIHJldHVybiBjb3VudFxuICAgICAgICAgICAgICAgICAgPyBgJHtjb3VudH0gb2YgJHt0b3RhbEFnZW50c30gYWdlbnRzIGhhdmUgJHt2dWxuZXJhYmlsaXRpZXNMZXZlbC50b0xvY2FsZUxvd2VyQ2FzZSgpfSB2dWxuZXJhYmlsaXRpZXMuYFxuICAgICAgICAgICAgICAgICAgOiB1bmRlZmluZWQ7XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7fVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICApXG4gICAgICAgICkuZmlsdGVyKCh2dWxuZXJhYmlsaXRpZXNSZXNwb25zZSkgPT4gdnVsbmVyYWJpbGl0aWVzUmVzcG9uc2UpO1xuXG4gICAgICAgIHByaW50ZXIuYWRkTGlzdCh7XG4gICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ1N1bW1hcnknLCBzdHlsZTogJ2gyJyB9LFxuICAgICAgICAgIGxpc3Q6IHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0NvdW50LFxuICAgICAgICB9KTtcblxuICAgICAgICBsb2coXG4gICAgICAgICAgJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJyxcbiAgICAgICAgICAnRmV0Y2hpbmcgb3ZlcnZpZXcgdnVsbmVyYWJpbGl0eSBkZXRlY3RvciB0b3AgMyBhZ2VudHMgYnkgY2F0ZWdvcnknLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgbG93UmFuayA9IGF3YWl0IFZ1bG5lcmFiaWxpdHlSZXF1ZXN0LnRvcEFnZW50Q291bnQoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgICdMb3cnLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBjb25zdCBtZWRpdW1SYW5rID0gYXdhaXQgVnVsbmVyYWJpbGl0eVJlcXVlc3QudG9wQWdlbnRDb3VudChcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgJ01lZGl1bScsXG4gICAgICAgICAgZmlsdGVycyxcbiAgICAgICAgICBwYXR0ZXJuXG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IGhpZ2hSYW5rID0gYXdhaXQgVnVsbmVyYWJpbGl0eVJlcXVlc3QudG9wQWdlbnRDb3VudChcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgJ0hpZ2gnLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBjb25zdCBjcml0aWNhbFJhbmsgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BBZ2VudENvdW50KFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgZnJvbSxcbiAgICAgICAgICB0byxcbiAgICAgICAgICAnQ3JpdGljYWwnLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBsb2coXG4gICAgICAgICAgJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJyxcbiAgICAgICAgICAnQWRkaW5nIG92ZXJ2aWV3IHZ1bG5lcmFiaWxpdHkgZGV0ZWN0b3IgdG9wIDMgYWdlbnRzIGJ5IGNhdGVnb3J5JyxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICAgIGlmIChjcml0aWNhbFJhbmsgJiYgY3JpdGljYWxSYW5rLmxlbmd0aCkge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICAgIHRleHQ6ICdUb3AgMyBhZ2VudHMgd2l0aCBjcml0aWNhbCBzZXZlcml0eSB2dWxuZXJhYmlsaXRpZXMnLFxuICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5idWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIGNyaXRpY2FsUmFuaywgYXBpSWQpO1xuICAgICAgICAgIHByaW50ZXIuYWRkTmV3TGluZSgpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGhpZ2hSYW5rICYmIGhpZ2hSYW5rLmxlbmd0aCkge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICAgIHRleHQ6ICdUb3AgMyBhZ2VudHMgd2l0aCBoaWdoIHNldmVyaXR5IHZ1bG5lcmFiaWxpdGllcycsXG4gICAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBhd2FpdCB0aGlzLmJ1aWxkQWdlbnRzVGFibGUoY29udGV4dCwgcHJpbnRlciwgaGlnaFJhbmssIGFwaUlkKTtcbiAgICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChtZWRpdW1SYW5rICYmIG1lZGl1bVJhbmsubGVuZ3RoKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDogJ1RvcCAzIGFnZW50cyB3aXRoIG1lZGl1bSBzZXZlcml0eSB2dWxuZXJhYmlsaXRpZXMnLFxuICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5idWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIG1lZGl1bVJhbmssIGFwaUlkKTtcbiAgICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChsb3dSYW5rICYmIGxvd1JhbmsubGVuZ3RoKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDogJ1RvcCAzIGFnZW50cyB3aXRoIGxvdyBzZXZlcml0eSB2dWxuZXJhYmlsaXRpZXMnLFxuICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5idWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIGxvd1JhbmssIGFwaUlkKTtcbiAgICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGxvZyhcbiAgICAgICAgICAncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLFxuICAgICAgICAgICdGZXRjaGluZyBvdmVydmlldyB2dWxuZXJhYmlsaXR5IGRldGVjdG9yIHRvcCAzIENWRXMnLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgY3ZlUmFuayA9IGF3YWl0IFZ1bG5lcmFiaWxpdHlSZXF1ZXN0LnRvcENWRUNvdW50KGNvbnRleHQsIGZyb20sIHRvLCBmaWx0ZXJzLCBwYXR0ZXJuKTtcbiAgICAgICAgbG9nKFxuICAgICAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICAgICAgJ0FkZGluZyBvdmVydmlldyB2dWxuZXJhYmlsaXR5IGRldGVjdG9yIHRvcCAzIENWRXMnLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgICAgaWYgKGN2ZVJhbmsgJiYgY3ZlUmFuay5sZW5ndGgpIHtcbiAgICAgICAgICBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHtcbiAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdUb3AgMyBDVkUnLCBzdHlsZTogJ2gyJyB9LFxuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAndG9wJywgbGFiZWw6ICdUb3AnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdjdmUnLCBsYWJlbDogJ0NWRScgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgICBpdGVtczogY3ZlUmFuay5tYXAoKGl0ZW0pID0+ICh7IHRvcDogY3ZlUmFuay5pbmRleE9mKGl0ZW0pICsgMSwgY3ZlOiBpdGVtIH0pKSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoc2VjdGlvbiA9PT0gJ292ZXJ2aWV3JyAmJiB0YWIgPT09ICdnZW5lcmFsJykge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0ZldGNoaW5nIHRvcCAzIGFnZW50cyB3aXRoIGxldmVsIDE1IGFsZXJ0cycsICdkZWJ1ZycpO1xuXG4gICAgICAgIGNvbnN0IGxldmVsMTVSYW5rID0gYXdhaXQgT3ZlcnZpZXdSZXF1ZXN0LnRvcExldmVsMTUoY29udGV4dCwgZnJvbSwgdG8sIGZpbHRlcnMsIHBhdHRlcm4pO1xuXG4gICAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnQWRkaW5nIHRvcCAzIGFnZW50cyB3aXRoIGxldmVsIDE1IGFsZXJ0cycsICdkZWJ1ZycpO1xuICAgICAgICBpZiAobGV2ZWwxNVJhbmsubGVuZ3RoKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6ICdUb3AgMyBhZ2VudHMgd2l0aCBsZXZlbCAxNSBhbGVydHMnLFxuICAgICAgICAgICAgc3R5bGU6ICdoMicsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5idWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIGxldmVsMTVSYW5rLCBhcGlJZCk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHNlY3Rpb24gPT09ICdvdmVydmlldycgJiYgdGFiID09PSAncG0nKSB7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgbW9zdCBjb21tb24gcm9vdGtpdHMnLCAnZGVidWcnKTtcbiAgICAgICAgY29uc3QgdG9wNVJvb3RraXRzUmFuayA9IGF3YWl0IFJvb3RjaGVja1JlcXVlc3QudG9wNVJvb3RraXRzRGV0ZWN0ZWQoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0FkZGluZyBtb3N0IGNvbW1vbiByb290a2l0cycsICdkZWJ1ZycpO1xuICAgICAgICBpZiAodG9wNVJvb3RraXRzUmFuayAmJiB0b3A1Um9vdGtpdHNSYW5rLmxlbmd0aCkge1xuICAgICAgICAgIHByaW50ZXJcbiAgICAgICAgICAgIC5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgICB0ZXh0OiAnTW9zdCBjb21tb24gcm9vdGtpdHMgZm91bmQgYW1vbmcgeW91ciBhZ2VudHMnLFxuICAgICAgICAgICAgICBzdHlsZTogJ2gyJyxcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICAgICAgdGV4dDpcbiAgICAgICAgICAgICAgICAnUm9vdGtpdHMgYXJlIGEgc2V0IG9mIHNvZnR3YXJlIHRvb2xzIHRoYXQgZW5hYmxlIGFuIHVuYXV0aG9yaXplZCB1c2VyIHRvIGdhaW4gY29udHJvbCBvZiBhIGNvbXB1dGVyIHN5c3RlbSB3aXRob3V0IGJlaW5nIGRldGVjdGVkLicsXG4gICAgICAgICAgICAgIHN0eWxlOiAnc3RhbmRhcmQnLFxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgICAgICAgIGl0ZW1zOiB0b3A1Um9vdGtpdHNSYW5rLm1hcCgoaXRlbSkgPT4ge1xuICAgICAgICAgICAgICAgIHJldHVybiB7IHRvcDogdG9wNVJvb3RraXRzUmFuay5pbmRleE9mKGl0ZW0pICsgMSwgbmFtZTogaXRlbSB9O1xuICAgICAgICAgICAgICB9KSxcbiAgICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICAgIHsgaWQ6ICd0b3AnLCBsYWJlbDogJ1RvcCcgfSxcbiAgICAgICAgICAgICAgICB7IGlkOiAnbmFtZScsIGxhYmVsOiAnUm9vdGtpdCcgfSxcbiAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgaGlkZGVuIHBpZHMnLCAnZGVidWcnKTtcbiAgICAgICAgY29uc3QgaGlkZGVuUGlkcyA9IGF3YWl0IFJvb3RjaGVja1JlcXVlc3QuYWdlbnRzV2l0aEhpZGRlblBpZHMoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBoaWRkZW5QaWRzICYmXG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6IGAke2hpZGRlblBpZHN9IG9mICR7dG90YWxBZ2VudHN9IGFnZW50cyBoYXZlIGhpZGRlbiBwcm9jZXNzZXNgLFxuICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgfSk7XG4gICAgICAgICFoaWRkZW5QaWRzICYmXG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDogYE5vIGFnZW50cyBoYXZlIGhpZGRlbiBwcm9jZXNzZXNgLFxuICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgY29uc3QgaGlkZGVuUG9ydHMgPSBhd2FpdCBSb290Y2hlY2tSZXF1ZXN0LmFnZW50c1dpdGhIaWRkZW5Qb3J0cyhcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgZmlsdGVycyxcbiAgICAgICAgICBwYXR0ZXJuXG4gICAgICAgICk7XG4gICAgICAgIGhpZGRlblBvcnRzICYmXG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6IGAke2hpZGRlblBvcnRzfSBvZiAke3RvdGFsQWdlbnRzfSBhZ2VudHMgaGF2ZSBoaWRkZW4gcG9ydHNgLFxuICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgfSk7XG4gICAgICAgICFoaWRkZW5Qb3J0cyAmJlxuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICB0ZXh0OiBgTm8gYWdlbnRzIGhhdmUgaGlkZGVuIHBvcnRzYCxcbiAgICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICAgIH0pO1xuICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKFsnb3ZlcnZpZXcnLCAnYWdlbnRzJ10uaW5jbHVkZXMoc2VjdGlvbikgJiYgdGFiID09PSAncGNpJykge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0ZldGNoaW5nIHRvcCBQQ0kgRFNTIHJlcXVpcmVtZW50cycsICdkZWJ1ZycpO1xuICAgICAgICBjb25zdCB0b3BQY2lSZXF1aXJlbWVudHMgPSBhd2FpdCBQQ0lSZXF1ZXN0LnRvcFBDSVJlcXVpcmVtZW50cyhcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgZmlsdGVycyxcbiAgICAgICAgICBwYXR0ZXJuXG4gICAgICAgICk7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICB0ZXh0OiAnTW9zdCBjb21tb24gUENJIERTUyByZXF1aXJlbWVudHMgYWxlcnRzIGZvdW5kJyxcbiAgICAgICAgICBzdHlsZTogJ2gyJyxcbiAgICAgICAgfSk7XG4gICAgICAgIGZvciAoY29uc3QgaXRlbSBvZiB0b3BQY2lSZXF1aXJlbWVudHMpIHtcbiAgICAgICAgICBjb25zdCBydWxlcyA9IGF3YWl0IFBDSVJlcXVlc3QuZ2V0UnVsZXNCeVJlcXVpcmVtZW50KFxuICAgICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICAgIGZyb20sXG4gICAgICAgICAgICB0byxcbiAgICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgICBpdGVtLFxuICAgICAgICAgICAgcGF0dGVyblxuICAgICAgICAgICk7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB0ZXh0OiBgUmVxdWlyZW1lbnQgJHtpdGVtfWAsIHN0eWxlOiAnaDMnIH0pO1xuXG4gICAgICAgICAgaWYgKFBDSVtpdGVtXSkge1xuICAgICAgICAgICAgY29uc3QgY29udGVudCA9XG4gICAgICAgICAgICAgIHR5cGVvZiBQQ0lbaXRlbV0gPT09ICdzdHJpbmcnID8geyB0ZXh0OiBQQ0lbaXRlbV0sIHN0eWxlOiAnc3RhbmRhcmQnIH0gOiBQQ0lbaXRlbV07XG4gICAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZShjb250ZW50KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBydWxlcyAmJlxuICAgICAgICAgICAgcnVsZXMubGVuZ3RoICYmXG4gICAgICAgICAgICBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHtcbiAgICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICAgIHsgaWQ6ICdydWxlSWQnLCBsYWJlbDogJ1J1bGUgSUQnIH0sXG4gICAgICAgICAgICAgICAgeyBpZDogJ3J1bGVEZXNjcmlwdGlvbicsIGxhYmVsOiAnRGVzY3JpcHRpb24nIH0sXG4gICAgICAgICAgICAgIF0sXG4gICAgICAgICAgICAgIGl0ZW1zOiBydWxlcyxcbiAgICAgICAgICAgICAgdGl0bGU6IGBUb3AgcnVsZXMgZm9yICR7aXRlbX0gcmVxdWlyZW1lbnRgLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKFsnb3ZlcnZpZXcnLCAnYWdlbnRzJ10uaW5jbHVkZXMoc2VjdGlvbikgJiYgdGFiID09PSAndHNjJykge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0ZldGNoaW5nIHRvcCBUU0MgcmVxdWlyZW1lbnRzJywgJ2RlYnVnJyk7XG4gICAgICAgIGNvbnN0IHRvcFRTQ1JlcXVpcmVtZW50cyA9IGF3YWl0IFRTQ1JlcXVlc3QudG9wVFNDUmVxdWlyZW1lbnRzKFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgZnJvbSxcbiAgICAgICAgICB0byxcbiAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgKTtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgIHRleHQ6ICdNb3N0IGNvbW1vbiBUU0MgcmVxdWlyZW1lbnRzIGFsZXJ0cyBmb3VuZCcsXG4gICAgICAgICAgc3R5bGU6ICdoMicsXG4gICAgICAgIH0pO1xuICAgICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgdG9wVFNDUmVxdWlyZW1lbnRzKSB7XG4gICAgICAgICAgY29uc3QgcnVsZXMgPSBhd2FpdCBUU0NSZXF1ZXN0LmdldFJ1bGVzQnlSZXF1aXJlbWVudChcbiAgICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgICBmcm9tLFxuICAgICAgICAgICAgdG8sXG4gICAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgICAgaXRlbSxcbiAgICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgICApO1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHsgdGV4dDogYFJlcXVpcmVtZW50ICR7aXRlbX1gLCBzdHlsZTogJ2gzJyB9KTtcblxuICAgICAgICAgIGlmIChUU0NbaXRlbV0pIHtcbiAgICAgICAgICAgIGNvbnN0IGNvbnRlbnQgPVxuICAgICAgICAgICAgICB0eXBlb2YgVFNDW2l0ZW1dID09PSAnc3RyaW5nJyA/IHsgdGV4dDogVFNDW2l0ZW1dLCBzdHlsZTogJ3N0YW5kYXJkJyB9IDogVFNDW2l0ZW1dO1xuICAgICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoY29udGVudCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcnVsZXMgJiZcbiAgICAgICAgICAgIHJ1bGVzLmxlbmd0aCAmJlxuICAgICAgICAgICAgcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgICB7IGlkOiAncnVsZUlkJywgbGFiZWw6ICdSdWxlIElEJyB9LFxuICAgICAgICAgICAgICAgIHsgaWQ6ICdydWxlRGVzY3JpcHRpb24nLCBsYWJlbDogJ0Rlc2NyaXB0aW9uJyB9LFxuICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgICBpdGVtczogcnVsZXMsXG4gICAgICAgICAgICAgIHRpdGxlOiBgVG9wIHJ1bGVzIGZvciAke2l0ZW19IHJlcXVpcmVtZW50YCxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChbJ292ZXJ2aWV3JywgJ2FnZW50cyddLmluY2x1ZGVzKHNlY3Rpb24pICYmIHRhYiA9PT0gJ2dkcHInKSB7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgdG9wIEdEUFIgcmVxdWlyZW1lbnRzJywgJ2RlYnVnJyk7XG4gICAgICAgIGNvbnN0IHRvcEdkcHJSZXF1aXJlbWVudHMgPSBhd2FpdCBHRFBSUmVxdWVzdC50b3BHRFBSUmVxdWlyZW1lbnRzKFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgZnJvbSxcbiAgICAgICAgICB0byxcbiAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgKTtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgIHRleHQ6ICdNb3N0IGNvbW1vbiBHRFBSIHJlcXVpcmVtZW50cyBhbGVydHMgZm91bmQnLFxuICAgICAgICAgIHN0eWxlOiAnaDInLFxuICAgICAgICB9KTtcbiAgICAgICAgZm9yIChjb25zdCBpdGVtIG9mIHRvcEdkcHJSZXF1aXJlbWVudHMpIHtcbiAgICAgICAgICBjb25zdCBydWxlcyA9IGF3YWl0IEdEUFJSZXF1ZXN0LmdldFJ1bGVzQnlSZXF1aXJlbWVudChcbiAgICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgICBmcm9tLFxuICAgICAgICAgICAgdG8sXG4gICAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgICAgaXRlbSxcbiAgICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgICApO1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHsgdGV4dDogYFJlcXVpcmVtZW50ICR7aXRlbX1gLCBzdHlsZTogJ2gzJyB9KTtcblxuICAgICAgICAgIGlmIChHRFBSICYmIEdEUFJbaXRlbV0pIHtcbiAgICAgICAgICAgIGNvbnN0IGNvbnRlbnQgPVxuICAgICAgICAgICAgICB0eXBlb2YgR0RQUltpdGVtXSA9PT0gJ3N0cmluZycgPyB7IHRleHQ6IEdEUFJbaXRlbV0sIHN0eWxlOiAnc3RhbmRhcmQnIH0gOiBHRFBSW2l0ZW1dO1xuICAgICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoY29udGVudCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcnVsZXMgJiZcbiAgICAgICAgICAgIHJ1bGVzLmxlbmd0aCAmJlxuICAgICAgICAgICAgcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgICB7IGlkOiAncnVsZUlkJywgbGFiZWw6ICdSdWxlIElEJyB9LFxuICAgICAgICAgICAgICAgIHsgaWQ6ICdydWxlRGVzY3JpcHRpb24nLCBsYWJlbDogJ0Rlc2NyaXB0aW9uJyB9LFxuICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgICBpdGVtczogcnVsZXMsXG4gICAgICAgICAgICAgIHRpdGxlOiBgVG9wIHJ1bGVzIGZvciAke2l0ZW19IHJlcXVpcmVtZW50YCxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHByaW50ZXIuYWRkTmV3TGluZSgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoc2VjdGlvbiA9PT0gJ292ZXJ2aWV3JyAmJiB0YWIgPT09ICdhdWRpdCcpIHtcbiAgICAgICAgbG9nKFxuICAgICAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICAgICAgJ0ZldGNoaW5nIGFnZW50cyB3aXRoIGhpZ2ggbnVtYmVyIG9mIGZhaWxlZCBzdWRvIGNvbW1hbmRzJyxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IGF1ZGl0QWdlbnRzTm9uU3VjY2VzcyA9IGF3YWl0IEF1ZGl0UmVxdWVzdC5nZXRUb3AzQWdlbnRzU3Vkb05vblN1Y2Nlc3NmdWwoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBpZiAoYXVkaXRBZ2VudHNOb25TdWNjZXNzICYmIGF1ZGl0QWdlbnRzTm9uU3VjY2Vzcy5sZW5ndGgpIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0FnZW50cyB3aXRoIGhpZ2ggbnVtYmVyIG9mIGZhaWxlZCBzdWRvIGNvbW1hbmRzJyxcbiAgICAgICAgICAgIHN0eWxlOiAnaDInLFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIGF3YWl0IHRoaXMuYnVpbGRBZ2VudHNUYWJsZShjb250ZXh0LCBwcmludGVyLCBhdWRpdEFnZW50c05vblN1Y2Nlc3MsIGFwaUlkKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBhdWRpdEFnZW50c0ZhaWxlZFN5c2NhbGwgPSBhd2FpdCBBdWRpdFJlcXVlc3QuZ2V0VG9wM0FnZW50c0ZhaWxlZFN5c2NhbGxzKFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgZnJvbSxcbiAgICAgICAgICB0byxcbiAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgKTtcbiAgICAgICAgaWYgKGF1ZGl0QWdlbnRzRmFpbGVkU3lzY2FsbCAmJiBhdWRpdEFnZW50c0ZhaWxlZFN5c2NhbGwubGVuZ3RoKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgIHsgaWQ6ICdhZ2VudCcsIGxhYmVsOiAnQWdlbnQgSUQnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdzeXNjYWxsX2lkJywgbGFiZWw6ICdTeXNjYWxsIElEJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnc3lzY2FsbF9zeXNjYWxsJywgbGFiZWw6ICdTeXNjYWxsJyB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIGl0ZW1zOiBhdWRpdEFnZW50c0ZhaWxlZFN5c2NhbGwubWFwKChpdGVtKSA9PiAoe1xuICAgICAgICAgICAgICBhZ2VudDogaXRlbS5hZ2VudCxcbiAgICAgICAgICAgICAgc3lzY2FsbF9pZDogaXRlbS5zeXNjYWxsLmlkLFxuICAgICAgICAgICAgICBzeXNjYWxsX3N5c2NhbGw6IGl0ZW0uc3lzY2FsbC5zeXNjYWxsLFxuICAgICAgICAgICAgfSkpLFxuICAgICAgICAgICAgdGl0bGU6IHtcbiAgICAgICAgICAgICAgdGV4dDogJ01vc3QgY29tbW9uIGZhaWxpbmcgc3lzY2FsbHMnLFxuICAgICAgICAgICAgICBzdHlsZTogJ2gyJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHNlY3Rpb24gPT09ICdvdmVydmlldycgJiYgdGFiID09PSAnZmltJykge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0ZldGNoaW5nIHRvcCAzIHJ1bGVzIGZvciBGSU0nLCAnZGVidWcnKTtcbiAgICAgICAgY29uc3QgcnVsZXMgPSBhd2FpdCBTeXNjaGVja1JlcXVlc3QudG9wM1J1bGVzKGNvbnRleHQsIGZyb20sIHRvLCBmaWx0ZXJzLCBwYXR0ZXJuKTtcblxuICAgICAgICBpZiAocnVsZXMgJiYgcnVsZXMubGVuZ3RoKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB0ZXh0OiAnVG9wIDMgRklNIHJ1bGVzJywgc3R5bGU6ICdoMicgfSkuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAncnVsZUlkJywgbGFiZWw6ICdSdWxlIElEJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAncnVsZURlc2NyaXB0aW9uJywgbGFiZWw6ICdEZXNjcmlwdGlvbicgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgICBpdGVtczogcnVsZXMsXG4gICAgICAgICAgICB0aXRsZToge1xuICAgICAgICAgICAgICB0ZXh0OiAnVG9wIDMgcnVsZXMgdGhhdCBhcmUgZ2VuZXJhdGluZyBtb3N0IGFsZXJ0cy4nLFxuICAgICAgICAgICAgICBzdHlsZTogJ3N0YW5kYXJkJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0ZldGNoaW5nIHRvcCAzIGFnZW50cyBmb3IgRklNJywgJ2RlYnVnJyk7XG4gICAgICAgIGNvbnN0IGFnZW50cyA9IGF3YWl0IFN5c2NoZWNrUmVxdWVzdC50b3AzYWdlbnRzKGNvbnRleHQsIGZyb20sIHRvLCBmaWx0ZXJzLCBwYXR0ZXJuKTtcblxuICAgICAgICBpZiAoYWdlbnRzICYmIGFnZW50cy5sZW5ndGgpIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgICAgICB0ZXh0OiAnQWdlbnRzIHdpdGggc3VzcGljaW91cyBGSU0gYWN0aXZpdHknLFxuICAgICAgICAgICAgc3R5bGU6ICdoMicsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDpcbiAgICAgICAgICAgICAgJ1RvcCAzIGFnZW50cyB0aGF0IGhhdmUgbW9zdCBGSU0gYWxlcnRzIGZyb20gbGV2ZWwgNyB0byBsZXZlbCAxNS4gVGFrZSBjYXJlIGFib3V0IHRoZW0uJyxcbiAgICAgICAgICAgIHN0eWxlOiAnc3RhbmRhcmQnLFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIGF3YWl0IHRoaXMuYnVpbGRBZ2VudHNUYWJsZShjb250ZXh0LCBwcmludGVyLCBhZ2VudHMsIGFwaUlkKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoc2VjdGlvbiA9PT0gJ2FnZW50cycgJiYgdGFiID09PSAnYXVkaXQnKSB7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCBgRmV0Y2hpbmcgbW9zdCBjb21tb24gZmFpbGVkIHN5c2NhbGxzYCwgJ2RlYnVnJyk7XG4gICAgICAgIGNvbnN0IGF1ZGl0RmFpbGVkU3lzY2FsbCA9IGF3YWl0IEF1ZGl0UmVxdWVzdC5nZXRUb3BGYWlsZWRTeXNjYWxscyhcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgZmlsdGVycyxcbiAgICAgICAgICBwYXR0ZXJuXG4gICAgICAgICk7XG4gICAgICAgIGF1ZGl0RmFpbGVkU3lzY2FsbCAmJlxuICAgICAgICAgIGF1ZGl0RmFpbGVkU3lzY2FsbC5sZW5ndGggJiZcbiAgICAgICAgICBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHtcbiAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgeyBpZDogJ2lkJywgbGFiZWw6ICdpZCcgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ3N5c2NhbGwnLCBsYWJlbDogJ1N5c2NhbGwnIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgaXRlbXM6IGF1ZGl0RmFpbGVkU3lzY2FsbCxcbiAgICAgICAgICAgIHRpdGxlOiAnTW9zdCBjb21tb24gZmFpbGluZyBzeXNjYWxscycsXG4gICAgICAgICAgfSk7XG4gICAgICB9XG5cbiAgICAgIGlmIChzZWN0aW9uID09PSAnYWdlbnRzJyAmJiB0YWIgPT09ICdmaW0nKSB7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLFxuICAgICAgICAgIGBGZXRjaGluZyBzeXNjaGVjayBkYXRhYmFzZSBmb3IgYWdlbnQgJHthZ2VudH1gLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcblxuICAgICAgICBjb25zdCBsYXN0U2NhblJlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICBgL3N5c2NoZWNrLyR7YWdlbnR9L2xhc3Rfc2NhbmAsXG4gICAgICAgICAge30sXG4gICAgICAgICAgeyBhcGlIb3N0SUQ6IGFwaUlkIH1cbiAgICAgICAgKTtcblxuICAgICAgICBpZiAobGFzdFNjYW5SZXNwb25zZSAmJiBsYXN0U2NhblJlc3BvbnNlLmRhdGEpIHtcbiAgICAgICAgICBjb25zdCBsYXN0U2NhbkRhdGEgPSBsYXN0U2NhblJlc3BvbnNlLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXTtcbiAgICAgICAgICBpZiAobGFzdFNjYW5EYXRhLnN0YXJ0ICYmIGxhc3RTY2FuRGF0YS5lbmQpIHtcbiAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgIHRleHQ6IGBMYXN0IGZpbGUgaW50ZWdyaXR5IG1vbml0b3Jpbmcgc2NhbiB3YXMgZXhlY3V0ZWQgZnJvbSAke2xhc3RTY2FuRGF0YS5zdGFydH0gdG8gJHtsYXN0U2NhbkRhdGEuZW5kfS5gLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSBlbHNlIGlmIChsYXN0U2NhbkRhdGEuc3RhcnQpIHtcbiAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgIHRleHQ6IGBGaWxlIGludGVncml0eSBtb25pdG9yaW5nIHNjYW4gaXMgY3VycmVudGx5IGluIHByb2dyZXNzIGZvciB0aGlzIGFnZW50IChzdGFydGVkIG9uICR7bGFzdFNjYW5EYXRhLnN0YXJ0fSkuYCxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgICB0ZXh0OiBgRmlsZSBpbnRlZ3JpdHkgbW9uaXRvcmluZyBzY2FuIGlzIGN1cnJlbnRseSBpbiBwcm9ncmVzcyBmb3IgdGhpcyBhZ2VudC5gLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHByaW50ZXIuYWRkTmV3TGluZSgpO1xuICAgICAgICB9XG5cbiAgICAgICAgbG9nKCdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsIGBGZXRjaGluZyBsYXN0IDEwIGRlbGV0ZWQgZmlsZXMgZm9yIEZJTWAsICdkZWJ1ZycpO1xuICAgICAgICBjb25zdCBsYXN0VGVuRGVsZXRlZCA9IGF3YWl0IFN5c2NoZWNrUmVxdWVzdC5sYXN0VGVuRGVsZXRlZEZpbGVzKFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgZnJvbSxcbiAgICAgICAgICB0byxcbiAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgKTtcblxuICAgICAgICBsYXN0VGVuRGVsZXRlZCAmJlxuICAgICAgICAgIGxhc3RUZW5EZWxldGVkLmxlbmd0aCAmJlxuICAgICAgICAgIHByaW50ZXIuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAncGF0aCcsIGxhYmVsOiAnUGF0aCcgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ2RhdGUnLCBsYWJlbDogJ0RhdGUnIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgaXRlbXM6IGxhc3RUZW5EZWxldGVkLFxuICAgICAgICAgICAgdGl0bGU6ICdMYXN0IDEwIGRlbGV0ZWQgZmlsZXMnLFxuICAgICAgICAgIH0pO1xuXG4gICAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCBgRmV0Y2hpbmcgbGFzdCAxMCBtb2RpZmllZCBmaWxlc2AsICdkZWJ1ZycpO1xuICAgICAgICBjb25zdCBsYXN0VGVuTW9kaWZpZWQgPSBhd2FpdCBTeXNjaGVja1JlcXVlc3QubGFzdFRlbk1vZGlmaWVkRmlsZXMoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuXG4gICAgICAgIGxhc3RUZW5Nb2RpZmllZCAmJlxuICAgICAgICAgIGxhc3RUZW5Nb2RpZmllZC5sZW5ndGggJiZcbiAgICAgICAgICBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHtcbiAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgeyBpZDogJ3BhdGgnLCBsYWJlbDogJ1BhdGgnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdkYXRlJywgbGFiZWw6ICdEYXRlJyB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIGl0ZW1zOiBsYXN0VGVuTW9kaWZpZWQsXG4gICAgICAgICAgICB0aXRsZTogJ0xhc3QgMTAgbW9kaWZpZWQgZmlsZXMnLFxuICAgICAgICAgIH0pO1xuICAgICAgfVxuXG4gICAgICBpZiAoc2VjdGlvbiA9PT0gJ2FnZW50cycgJiYgdGFiID09PSAnc3lzY29sbGVjdG9yJykge1xuICAgICAgICBsb2coXG4gICAgICAgICAgJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJyxcbiAgICAgICAgICBgRmV0Y2hpbmcgaGFyZHdhcmUgaW5mb3JtYXRpb24gZm9yIGFnZW50ICR7YWdlbnR9YCxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IHJlcXVlc3RzU3lzY29sbGVjdG9yTGlzdHMgPSBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgZW5kcG9pbnQ6IGAvc3lzY29sbGVjdG9yLyR7YWdlbnR9L2hhcmR3YXJlYCxcbiAgICAgICAgICAgIGxvZ2dlck1lc3NhZ2U6IGBGZXRjaGluZyBIYXJkd2FyZSBpbmZvcm1hdGlvbiBmb3IgYWdlbnQgJHthZ2VudH1gLFxuICAgICAgICAgICAgbGlzdDoge1xuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnSGFyZHdhcmUgaW5mb3JtYXRpb24nLCBzdHlsZTogJ2gyJyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIG1hcFJlc3BvbnNlOiAoaGFyZHdhcmUpID0+IFtcbiAgICAgICAgICAgICAgaGFyZHdhcmUuY3B1ICYmIGhhcmR3YXJlLmNwdS5jb3JlcyAmJiBgJHtoYXJkd2FyZS5jcHUuY29yZXN9IGNvcmVzYCxcbiAgICAgICAgICAgICAgaGFyZHdhcmUuY3B1ICYmIGhhcmR3YXJlLmNwdS5uYW1lLFxuICAgICAgICAgICAgICBoYXJkd2FyZS5yYW0gJiZcbiAgICAgICAgICAgICAgICBoYXJkd2FyZS5yYW0udG90YWwgJiZcbiAgICAgICAgICAgICAgICBgJHtOdW1iZXIoaGFyZHdhcmUucmFtLnRvdGFsIC8gMTAyNCAvIDEwMjQpLnRvRml4ZWQoMil9R0IgUkFNYCxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudH0vb3NgLFxuICAgICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIE9TIGluZm9ybWF0aW9uIGZvciBhZ2VudCAke2FnZW50fWAsXG4gICAgICAgICAgICBsaXN0OiB7XG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdPUyBpbmZvcm1hdGlvbicsIHN0eWxlOiAnaDInIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgbWFwUmVzcG9uc2U6IChvc0RhdGEpID0+IFtcbiAgICAgICAgICAgICAgb3NEYXRhLnN5c25hbWUsXG4gICAgICAgICAgICAgIG9zRGF0YS52ZXJzaW9uLFxuICAgICAgICAgICAgICBvc0RhdGEuYXJjaGl0ZWN0dXJlLFxuICAgICAgICAgICAgICBvc0RhdGEucmVsZWFzZSxcbiAgICAgICAgICAgICAgb3NEYXRhLm9zICYmXG4gICAgICAgICAgICAgICAgb3NEYXRhLm9zLm5hbWUgJiZcbiAgICAgICAgICAgICAgICBvc0RhdGEub3MudmVyc2lvbiAmJlxuICAgICAgICAgICAgICAgIGAke29zRGF0YS5vcy5uYW1lfSAke29zRGF0YS5vcy52ZXJzaW9ufWAsXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIF07XG5cbiAgICAgICAgY29uc3Qgc3lzY29sbGVjdG9yTGlzdHMgPSBhd2FpdCBQcm9taXNlLmFsbChcbiAgICAgICAgICByZXF1ZXN0c1N5c2NvbGxlY3Rvckxpc3RzLm1hcChhc3luYyAocmVxdWVzdFN5c2NvbGxlY3RvcikgPT4ge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgbG9nKCdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsIHJlcXVlc3RTeXNjb2xsZWN0b3IubG9nZ2VyTWVzc2FnZSwgJ2RlYnVnJyk7XG4gICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlU3lzY29sbGVjdG9yID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgICAgICByZXF1ZXN0U3lzY29sbGVjdG9yLmVuZHBvaW50LFxuICAgICAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgIGNvbnN0IFtkYXRhXSA9XG4gICAgICAgICAgICAgICAgKHJlc3BvbnNlU3lzY29sbGVjdG9yICYmXG4gICAgICAgICAgICAgICAgICByZXNwb25zZVN5c2NvbGxlY3Rvci5kYXRhICYmXG4gICAgICAgICAgICAgICAgICByZXNwb25zZVN5c2NvbGxlY3Rvci5kYXRhLmRhdGEgJiZcbiAgICAgICAgICAgICAgICAgIHJlc3BvbnNlU3lzY29sbGVjdG9yLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtcykgfHxcbiAgICAgICAgICAgICAgICBbXTtcbiAgICAgICAgICAgICAgaWYgKGRhdGEpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgICAgLi4ucmVxdWVzdFN5c2NvbGxlY3Rvci5saXN0LFxuICAgICAgICAgICAgICAgICAgbGlzdDogcmVxdWVzdFN5c2NvbGxlY3Rvci5tYXBSZXNwb25zZShkYXRhKSxcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSlcbiAgICAgICAgKTtcblxuICAgICAgICBpZiAoc3lzY29sbGVjdG9yTGlzdHMpIHtcbiAgICAgICAgICBzeXNjb2xsZWN0b3JMaXN0c1xuICAgICAgICAgICAgLmZpbHRlcigoc3lzY29sbGVjdG9yTGlzdCkgPT4gc3lzY29sbGVjdG9yTGlzdClcbiAgICAgICAgICAgIC5mb3JFYWNoKChzeXNjb2xsZWN0b3JMaXN0KSA9PiBwcmludGVyLmFkZExpc3Qoc3lzY29sbGVjdG9yTGlzdCkpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgdnVsbmVyYWJpbGl0aWVzUmVxdWVzdHMgPSBbJ0NyaXRpY2FsJywgJ0hpZ2gnXTtcblxuICAgICAgICBjb25zdCB2dWxuZXJhYmlsaXRpZXNSZXNwb25zZXNJdGVtcyA9IChcbiAgICAgICAgICBhd2FpdCBQcm9taXNlLmFsbChcbiAgICAgICAgICAgIHZ1bG5lcmFiaWxpdGllc1JlcXVlc3RzLm1hcChhc3luYyAodnVsbmVyYWJpbGl0aWVzTGV2ZWwpID0+IHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBsb2coXG4gICAgICAgICAgICAgICAgICAncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLFxuICAgICAgICAgICAgICAgICAgYEZldGNoaW5nIHRvcCAke3Z1bG5lcmFiaWxpdGllc0xldmVsfSBwYWNrYWdlc2AsXG4gICAgICAgICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICAgIHJldHVybiBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BQYWNrYWdlcyhcbiAgICAgICAgICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgICAgICAgICBmcm9tLFxuICAgICAgICAgICAgICAgICAgdG8sXG4gICAgICAgICAgICAgICAgICB2dWxuZXJhYmlsaXRpZXNMZXZlbCxcbiAgICAgICAgICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgICAgICAgICBwYXR0ZXJuXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgKVxuICAgICAgICApXG4gICAgICAgICAgLmZpbHRlcigodnVsbmVyYWJpbGl0aWVzUmVzcG9uc2UpID0+IHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlKVxuICAgICAgICAgIC5mbGF0KCk7XG5cbiAgICAgICAgaWYgKHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0l0ZW1zICYmIHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0l0ZW1zLmxlbmd0aCkge1xuICAgICAgICAgIHByaW50ZXIuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ1Z1bG5lcmFibGUgcGFja2FnZXMgZm91bmQgKGxhc3QgMjQgaG91cnMpJywgc3R5bGU6ICdoMicgfSxcbiAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgeyBpZDogJ3BhY2thZ2UnLCBsYWJlbDogJ1BhY2thZ2UnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdzZXZlcml0eScsIGxhYmVsOiAnU2V2ZXJpdHknIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgaXRlbXM6IHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0l0ZW1zLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChzZWN0aW9uID09PSAnYWdlbnRzJyAmJiB0YWIgPT09ICd2dWxzJykge1xuICAgICAgICBjb25zdCB0b3BDcml0aWNhbFBhY2thZ2VzID0gYXdhaXQgVnVsbmVyYWJpbGl0eVJlcXVlc3QudG9wUGFja2FnZXNXaXRoQ1ZFKFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgZnJvbSxcbiAgICAgICAgICB0byxcbiAgICAgICAgICAnQ3JpdGljYWwnLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBpZiAodG9wQ3JpdGljYWxQYWNrYWdlcyAmJiB0b3BDcml0aWNhbFBhY2thZ2VzLmxlbmd0aCkge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHsgdGV4dDogJ0NyaXRpY2FsIHNldmVyaXR5Jywgc3R5bGU6ICdoMicgfSk7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDpcbiAgICAgICAgICAgICAgJ1RoZXNlIHZ1bG5lcmFiaWx0aWVzIGFyZSBjcml0aWNhbCwgcGxlYXNlIHJldmlldyB5b3VyIGFnZW50LiBDbGljayBvbiBlYWNoIGxpbmsgdG8gcmVhZCBtb3JlIGFib3V0IGVhY2ggZm91bmQgdnVsbmVyYWJpbGl0eS4nLFxuICAgICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgY29uc3QgY3VzdG9tdWwgPSBbXTtcbiAgICAgICAgICBmb3IgKGNvbnN0IGNyaXRpY2FsIG9mIHRvcENyaXRpY2FsUGFja2FnZXMpIHtcbiAgICAgICAgICAgIGN1c3RvbXVsLnB1c2goeyB0ZXh0OiBjcml0aWNhbC5wYWNrYWdlLCBzdHlsZTogJ3N0YW5kYXJkJyB9KTtcbiAgICAgICAgICAgIGN1c3RvbXVsLnB1c2goe1xuICAgICAgICAgICAgICB1bDogY3JpdGljYWwucmVmZXJlbmNlcy5tYXAoKGl0ZW0pID0+ICh7XG4gICAgICAgICAgICAgICAgdGV4dDogaXRlbS5zdWJzdHJpbmcoMCwgODApICsgJy4uLicsXG4gICAgICAgICAgICAgICAgbGluazogaXRlbSxcbiAgICAgICAgICAgICAgICBjb2xvcjogJyMxRUE1QzgnLFxuICAgICAgICAgICAgICB9KSksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB1bDogY3VzdG9tdWwgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCB0b3BIaWdoUGFja2FnZXMgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BQYWNrYWdlc1dpdGhDVkUoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgICdIaWdoJyxcbiAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgKTtcbiAgICAgICAgaWYgKHRvcEhpZ2hQYWNrYWdlcyAmJiB0b3BIaWdoUGFja2FnZXMubGVuZ3RoKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB0ZXh0OiAnSGlnaCBzZXZlcml0eScsIHN0eWxlOiAnaDInIH0pO1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICAgIHRleHQ6ICdDbGljayBvbiBlYWNoIGxpbmsgdG8gcmVhZCBtb3JlIGFib3V0IGVhY2ggZm91bmQgdnVsbmVyYWJpbGl0eS4nLFxuICAgICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgY29uc3QgY3VzdG9tdWwgPSBbXTtcbiAgICAgICAgICBmb3IgKGNvbnN0IGNyaXRpY2FsIG9mIHRvcEhpZ2hQYWNrYWdlcykge1xuICAgICAgICAgICAgY3VzdG9tdWwucHVzaCh7IHRleHQ6IGNyaXRpY2FsLnBhY2thZ2UsIHN0eWxlOiAnc3RhbmRhcmQnIH0pO1xuICAgICAgICAgICAgY3VzdG9tdWwucHVzaCh7XG4gICAgICAgICAgICAgIHVsOiBjcml0aWNhbC5yZWZlcmVuY2VzLm1hcCgoaXRlbSkgPT4gKHtcbiAgICAgICAgICAgICAgICB0ZXh0OiBpdGVtLFxuICAgICAgICAgICAgICAgIGNvbG9yOiAnIzFFQTVDOCcsXG4gICAgICAgICAgICAgIH0pKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICBjdXN0b211bCAmJiBjdXN0b211bC5sZW5ndGggJiYgcHJpbnRlci5hZGRDb250ZW50KHsgdWw6IGN1c3RvbXVsIH0pO1xuICAgICAgICAgIHByaW50ZXIuYWRkTmV3TGluZSgpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGdldENvbmZpZ1Jvd3MoZGF0YSwgbGFiZWxzKSB7XG4gICAgbG9nKCdyZXBvcnRpbmc6Z2V0Q29uZmlnUm93cycsIGBCdWlsZGluZyBjb25maWd1cmF0aW9uIHJvd3NgLCAnaW5mbycpO1xuICAgIGNvbnN0IHJlc3VsdCA9IFtdO1xuICAgIGZvciAobGV0IHByb3AgaW4gZGF0YSB8fCBbXSkge1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoZGF0YVtwcm9wXSkpIHtcbiAgICAgICAgZGF0YVtwcm9wXS5mb3JFYWNoKCh4LCBpZHgpID0+IHtcbiAgICAgICAgICBpZiAodHlwZW9mIHggPT09ICdvYmplY3QnKSBkYXRhW3Byb3BdW2lkeF0gPSBKU09OLnN0cmluZ2lmeSh4KTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXN1bHQucHVzaChbKGxhYmVscyB8fCB7fSlbcHJvcF0gfHwgS2V5RXF1aXZhbGVuY2VbcHJvcF0gfHwgcHJvcCwgZGF0YVtwcm9wXSB8fCAnLSddKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0Q29uZmlnVGFibGVzKGRhdGEsIHNlY3Rpb24sIHRhYiwgYXJyYXkgPSBbXSkge1xuICAgIGxvZygncmVwb3J0aW5nOmdldENvbmZpZ1RhYmxlcycsIGBCdWlsZGluZyBjb25maWd1cmF0aW9uIHRhYmxlc2AsICdpbmZvJyk7XG4gICAgbGV0IHBsYWluRGF0YSA9IHt9O1xuICAgIGNvbnN0IG5lc3RlZERhdGEgPSBbXTtcbiAgICBjb25zdCB0YWJsZURhdGEgPSBbXTtcblxuICAgIGlmIChkYXRhLmxlbmd0aCA9PT0gMSAmJiBBcnJheS5pc0FycmF5KGRhdGEpKSB7XG4gICAgICB0YWJsZURhdGFbc2VjdGlvbi5jb25maWdbdGFiXS5jb25maWd1cmF0aW9uXSA9IGRhdGE7XG4gICAgfSBlbHNlIHtcbiAgICAgIGZvciAobGV0IGtleSBpbiBkYXRhKSB7XG4gICAgICAgIGlmIChcbiAgICAgICAgICAodHlwZW9mIGRhdGFba2V5XSAhPT0gJ29iamVjdCcgJiYgIUFycmF5LmlzQXJyYXkoZGF0YVtrZXldKSkgfHxcbiAgICAgICAgICAoQXJyYXkuaXNBcnJheShkYXRhW2tleV0pICYmIHR5cGVvZiBkYXRhW2tleV1bMF0gIT09ICdvYmplY3QnKVxuICAgICAgICApIHtcbiAgICAgICAgICBwbGFpbkRhdGFba2V5XSA9XG4gICAgICAgICAgICBBcnJheS5pc0FycmF5KGRhdGFba2V5XSkgJiYgdHlwZW9mIGRhdGFba2V5XVswXSAhPT0gJ29iamVjdCdcbiAgICAgICAgICAgICAgPyBkYXRhW2tleV0ubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4gdHlwZW9mIHggPT09ICdvYmplY3QnID8gSlNPTi5zdHJpbmdpZnkoeCkgOiB4ICsgJ1xcbic7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgOiBkYXRhW2tleV07XG4gICAgICAgIH0gZWxzZSBpZiAoQXJyYXkuaXNBcnJheShkYXRhW2tleV0pICYmIHR5cGVvZiBkYXRhW2tleV1bMF0gPT09ICdvYmplY3QnKSB7XG4gICAgICAgICAgdGFibGVEYXRhW2tleV0gPSBkYXRhW2tleV07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgaWYgKHNlY3Rpb24uaXNHcm91cENvbmZpZyAmJiBbJ3BhY2snLCAnY29udGVudCddLmluY2x1ZGVzKGtleSkpIHtcbiAgICAgICAgICAgIHRhYmxlRGF0YVtrZXldID0gW2RhdGFba2V5XV07XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIG5lc3RlZERhdGEucHVzaChkYXRhW2tleV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICBhcnJheS5wdXNoKHtcbiAgICAgIHRpdGxlOiAoc2VjdGlvbi5vcHRpb25zIHx8IHt9KS5oaWRlSGVhZGVyXG4gICAgICAgID8gJydcbiAgICAgICAgOiAoc2VjdGlvbi50YWJzIHx8IFtdKVt0YWJdIHx8XG4gICAgICAgICAgKHNlY3Rpb24uaXNHcm91cENvbmZpZyA/ICgoc2VjdGlvbi5sYWJlbHMgfHwgW10pWzBdIHx8IFtdKVt0YWJdIDogJycpLFxuICAgICAgY29sdW1uczogWycnLCAnJ10sXG4gICAgICB0eXBlOiAnY29uZmlnJyxcbiAgICAgIHJvd3M6IHRoaXMuZ2V0Q29uZmlnUm93cyhwbGFpbkRhdGEsIChzZWN0aW9uLmxhYmVscyB8fCBbXSlbMF0pLFxuICAgIH0pO1xuICAgIGZvciAobGV0IGtleSBpbiB0YWJsZURhdGEpIHtcbiAgICAgIGNvbnN0IGNvbHVtbnMgPSBPYmplY3Qua2V5cyh0YWJsZURhdGFba2V5XVswXSk7XG4gICAgICBjb2x1bW5zLmZvckVhY2goKGNvbCwgaSkgPT4ge1xuICAgICAgICBjb2x1bW5zW2ldID0gY29sWzBdLnRvVXBwZXJDYXNlKCkgKyBjb2wuc2xpY2UoMSk7XG4gICAgICB9KTtcblxuICAgICAgY29uc3Qgcm93cyA9IHRhYmxlRGF0YVtrZXldLm1hcCgoeCkgPT4ge1xuICAgICAgICBsZXQgcm93ID0gW107XG4gICAgICAgIGZvciAobGV0IGtleSBpbiB4KSB7XG4gICAgICAgICAgcm93LnB1c2goXG4gICAgICAgICAgICB0eXBlb2YgeFtrZXldICE9PSAnb2JqZWN0J1xuICAgICAgICAgICAgICA/IHhba2V5XVxuICAgICAgICAgICAgICA6IEFycmF5LmlzQXJyYXkoeFtrZXldKVxuICAgICAgICAgICAgICA/IHhba2V5XS5tYXAoKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgIHJldHVybiB4ICsgJ1xcbic7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgOiBKU09OLnN0cmluZ2lmeSh4W2tleV0pXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgICB3aGlsZSAocm93Lmxlbmd0aCA8IGNvbHVtbnMubGVuZ3RoKSB7XG4gICAgICAgICAgcm93LnB1c2goJy0nKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcm93O1xuICAgICAgfSk7XG4gICAgICBhcnJheS5wdXNoKHtcbiAgICAgICAgdGl0bGU6ICgoc2VjdGlvbi5sYWJlbHMgfHwgW10pWzBdIHx8IFtdKVtrZXldIHx8ICcnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBjb2x1bW5zLFxuICAgICAgICByb3dzLFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgbmVzdGVkRGF0YS5mb3JFYWNoKChuZXN0KSA9PiB7XG4gICAgICB0aGlzLmdldENvbmZpZ1RhYmxlcyhuZXN0LCBzZWN0aW9uLCB0YWIgKyAxLCBhcnJheSk7XG4gICAgfSk7XG5cbiAgICByZXR1cm4gYXJyYXk7XG4gIH1cblxuICAvKipcbiAgICogQ3JlYXRlIGEgcmVwb3J0IGZvciB0aGUgbW9kdWxlc1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMgeyp9IHJlcG9ydHMgbGlzdCBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjcmVhdGVSZXBvcnRzTW9kdWxlcyhcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogS2liYW5hUmVxdWVzdCxcbiAgICByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5XG4gICkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzTW9kdWxlcycsIGBSZXBvcnQgc3RhcnRlZGAsICdpbmZvJyk7XG4gICAgICBjb25zdCB7XG4gICAgICAgIGFycmF5LFxuICAgICAgICBhZ2VudHMsXG4gICAgICAgIGJyb3dzZXJUaW1lem9uZSxcbiAgICAgICAgc2VhcmNoQmFyLFxuICAgICAgICBmaWx0ZXJzLFxuICAgICAgICB0aW1lLFxuICAgICAgICB0YWJsZXMsXG4gICAgICAgIG5hbWUsXG4gICAgICAgIHNlY3Rpb24sXG4gICAgICB9ID0gcmVxdWVzdC5ib2R5O1xuICAgICAgY29uc3QgeyBtb2R1bGVJRCB9ID0gcmVxdWVzdC5wYXJhbXM7XG4gICAgICBjb25zdCB7IGlkOiBhcGlJZCwgcGF0dGVybjogaW5kZXhQYXR0ZXJuIH0gPSByZXF1ZXN0LmhlYWRlcnM7XG4gICAgICBjb25zdCB7IGZyb20sIHRvIH0gPSB0aW1lIHx8IHt9O1xuICAgICAgLy8gSW5pdFxuICAgICAgY29uc3QgcHJpbnRlciA9IG5ldyBSZXBvcnRQcmludGVyKCk7XG4gICAgICBjb25zdCB7IHVzZXJuYW1lOiB1c2VySUQgfSA9IGF3YWl0IGNvbnRleHQud2F6dWguc2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCk7XG4gICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMocGF0aC5qb2luKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgsIHVzZXJJRCkpO1xuXG4gICAgICBhd2FpdCB0aGlzLnJlbmRlckhlYWRlcihjb250ZXh0LCBwcmludGVyLCBzZWN0aW9uLCBtb2R1bGVJRCwgYWdlbnRzLCBhcGlJZCk7XG5cbiAgICAgIGNvbnN0IFtzYW5pdGl6ZWRGaWx0ZXJzLCBhZ2VudHNGaWx0ZXJdID0gZmlsdGVyc1xuICAgICAgICA/IHRoaXMuc2FuaXRpemVLaWJhbmFGaWx0ZXJzKGZpbHRlcnMsIHNlYXJjaEJhcilcbiAgICAgICAgOiBbZmFsc2UsIGZhbHNlXTtcblxuICAgICAgaWYgKHRpbWUgJiYgc2FuaXRpemVkRmlsdGVycykge1xuICAgICAgICBwcmludGVyLmFkZFRpbWVSYW5nZUFuZEZpbHRlcnMoZnJvbSwgdG8sIHNhbml0aXplZEZpbHRlcnMsIGJyb3dzZXJUaW1lem9uZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0aW1lKSB7XG4gICAgICAgIGF3YWl0IHRoaXMuZXh0ZW5kZWRJbmZvcm1hdGlvbihcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIHByaW50ZXIsXG4gICAgICAgICAgc2VjdGlvbixcbiAgICAgICAgICBtb2R1bGVJRCxcbiAgICAgICAgICBhcGlJZCxcbiAgICAgICAgICBuZXcgRGF0ZShmcm9tKS5nZXRUaW1lKCksXG4gICAgICAgICAgbmV3IERhdGUodG8pLmdldFRpbWUoKSxcbiAgICAgICAgICBzYW5pdGl6ZWRGaWx0ZXJzLFxuICAgICAgICAgIGluZGV4UGF0dGVybixcbiAgICAgICAgICBhZ2VudHNcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgcHJpbnRlci5hZGRWaXN1YWxpemF0aW9ucyhhcnJheSwgYWdlbnRzLCBtb2R1bGVJRCk7XG5cbiAgICAgIGlmICh0YWJsZXMpIHtcbiAgICAgICAgcHJpbnRlci5hZGRUYWJsZXModGFibGVzKTtcbiAgICAgIH1cblxuICAgICAgLy9hZGQgYXV0aG9yaXplZCBhZ2VudHNcbiAgICAgIGlmIChhZ2VudHNGaWx0ZXIpIHtcbiAgICAgICAgcHJpbnRlci5hZGRBZ2VudHNGaWx0ZXJzKGFnZW50c0ZpbHRlcik7XG4gICAgICB9XG5cbiAgICAgIGF3YWl0IHByaW50ZXIucHJpbnQocGF0aC5qb2luKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgsIHVzZXJJRCwgbmFtZSkpO1xuXG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7XG4gICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICBtZXNzYWdlOiBgUmVwb3J0ICR7bmFtZX0gd2FzIGNyZWF0ZWRgLFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDUwMjksIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBDcmVhdGUgYSByZXBvcnQgZm9yIHRoZSBncm91cHNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHsqfSByZXBvcnRzIGxpc3Qgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgY3JlYXRlUmVwb3J0c0dyb3VwcyhcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogS2liYW5hUmVxdWVzdCxcbiAgICByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5XG4gICkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzR3JvdXBzJywgYFJlcG9ydCBzdGFydGVkYCwgJ2luZm8nKTtcbiAgICAgIGNvbnN0IHsgYnJvd3NlclRpbWV6b25lLCBzZWFyY2hCYXIsIGZpbHRlcnMsIHRpbWUsIG5hbWUsIGNvbXBvbmVudHMgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIGNvbnN0IHsgZ3JvdXBJRCB9ID0gcmVxdWVzdC5wYXJhbXM7XG4gICAgICBjb25zdCB7IGlkOiBhcGlJZCwgcGF0dGVybjogaW5kZXhQYXR0ZXJuIH0gPSByZXF1ZXN0LmhlYWRlcnM7XG4gICAgICBjb25zdCB7IGZyb20sIHRvIH0gPSB0aW1lIHx8IHt9O1xuICAgICAgLy8gSW5pdFxuICAgICAgY29uc3QgcHJpbnRlciA9IG5ldyBSZXBvcnRQcmludGVyKCk7XG5cbiAgICAgIGNvbnN0IHsgdXNlcm5hbWU6IHVzZXJJRCB9ID0gYXdhaXQgY29udGV4dC53YXp1aC5zZWN1cml0eS5nZXRDdXJyZW50VXNlcihyZXF1ZXN0LCBjb250ZXh0KTtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgdXNlcklEKSk7XG5cbiAgICAgIGxldCB0YWJsZXMgPSBbXTtcbiAgICAgIGNvbnN0IGVxdWl2YWxlbmNlcyA9IHtcbiAgICAgICAgbG9jYWxmaWxlOiAnTG9jYWwgZmlsZXMnLFxuICAgICAgICBvc3F1ZXJ5OiAnT3NxdWVyeScsXG4gICAgICAgIGNvbW1hbmQ6ICdDb21tYW5kJyxcbiAgICAgICAgc3lzY2hlY2s6ICdTeXNjaGVjaycsXG4gICAgICAgICdvcGVuLXNjYXAnOiAnT3BlblNDQVAnLFxuICAgICAgICAnY2lzLWNhdCc6ICdDSVMtQ0FUJyxcbiAgICAgICAgc3lzY29sbGVjdG9yOiAnU3lzY29sbGVjdG9yJyxcbiAgICAgICAgcm9vdGNoZWNrOiAnUm9vdGNoZWNrJyxcbiAgICAgICAgbGFiZWxzOiAnTGFiZWxzJyxcbiAgICAgICAgc2NhOiAnU2VjdXJpdHkgY29uZmlndXJhdGlvbiBhc3Nlc3NtZW50JyxcbiAgICAgIH07XG4gICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICB0ZXh0OiBgR3JvdXAgJHtncm91cElEfSBjb25maWd1cmF0aW9uYCxcbiAgICAgICAgc3R5bGU6ICdoMScsXG4gICAgICB9KTtcblxuICAgICAgaWYgKGNvbXBvbmVudHNbJzAnXSkge1xuICAgICAgICBsZXQgY29uZmlndXJhdGlvbiA9IHt9O1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGNvbnN0IGNvbmZpZ3VyYXRpb25SZXNwb25zZSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgIGAvZ3JvdXBzLyR7Z3JvdXBJRH0vY29uZmlndXJhdGlvbmAsXG4gICAgICAgICAgICB7fSxcbiAgICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICAgKTtcbiAgICAgICAgICBjb25maWd1cmF0aW9uID0gY29uZmlndXJhdGlvblJlc3BvbnNlLmRhdGEuZGF0YTtcbiAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzR3JvdXBzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgJ2RlYnVnJyk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoXG4gICAgICAgICAgY29uZmlndXJhdGlvbi5hZmZlY3RlZF9pdGVtcy5sZW5ndGggPiAwICYmXG4gICAgICAgICAgT2JqZWN0LmtleXMoY29uZmlndXJhdGlvbi5hZmZlY3RlZF9pdGVtc1swXS5jb25maWcpLmxlbmd0aFxuICAgICAgICApIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0NvbmZpZ3VyYXRpb25zJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAxNCwgY29sb3I6ICcjMDAwJyB9LFxuICAgICAgICAgICAgbWFyZ2luOiBbMCwgMTAsIDAsIDE1XSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBjb25zdCBzZWN0aW9uID0ge1xuICAgICAgICAgICAgbGFiZWxzOiBbXSxcbiAgICAgICAgICAgIGlzR3JvdXBDb25maWc6IHRydWUsXG4gICAgICAgICAgfTtcbiAgICAgICAgICBmb3IgKGxldCBjb25maWcgb2YgY29uZmlndXJhdGlvbi5hZmZlY3RlZF9pdGVtcykge1xuICAgICAgICAgICAgbGV0IGZpbHRlclRpdGxlID0gJyc7XG4gICAgICAgICAgICBsZXQgaW5kZXggPSAwO1xuICAgICAgICAgICAgZm9yIChsZXQgZmlsdGVyIG9mIE9iamVjdC5rZXlzKGNvbmZpZy5maWx0ZXJzKSkge1xuICAgICAgICAgICAgICBmaWx0ZXJUaXRsZSA9IGZpbHRlclRpdGxlLmNvbmNhdChgJHtmaWx0ZXJ9OiAke2NvbmZpZy5maWx0ZXJzW2ZpbHRlcl19YCk7XG4gICAgICAgICAgICAgIGlmIChpbmRleCA8IE9iamVjdC5rZXlzKGNvbmZpZy5maWx0ZXJzKS5sZW5ndGggLSAxKSB7XG4gICAgICAgICAgICAgICAgZmlsdGVyVGl0bGUgPSBmaWx0ZXJUaXRsZS5jb25jYXQoJyB8ICcpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGluZGV4Kys7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgICB0ZXh0OiBmaWx0ZXJUaXRsZSxcbiAgICAgICAgICAgICAgc3R5bGU6ICdoNCcsXG4gICAgICAgICAgICAgIG1hcmdpbjogWzAsIDAsIDAsIDEwXSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgbGV0IGlkeCA9IDA7XG4gICAgICAgICAgICBzZWN0aW9uLnRhYnMgPSBbXTtcbiAgICAgICAgICAgIGZvciAobGV0IF9kIG9mIE9iamVjdC5rZXlzKGNvbmZpZy5jb25maWcpKSB7XG4gICAgICAgICAgICAgIGZvciAobGV0IGMgb2YgQWdlbnRDb25maWd1cmF0aW9uLmNvbmZpZ3VyYXRpb25zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChsZXQgcyBvZiBjLnNlY3Rpb25zKSB7XG4gICAgICAgICAgICAgICAgICBzZWN0aW9uLm9wdHMgPSBzLm9wdHMgfHwge307XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCBjbiBvZiBzLmNvbmZpZyB8fCBbXSkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoY24uY29uZmlndXJhdGlvbiA9PT0gX2QpIHtcbiAgICAgICAgICAgICAgICAgICAgICBzZWN0aW9uLmxhYmVscyA9IHMubGFiZWxzIHx8IFtbXV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIGZvciAobGV0IHdvIG9mIHMud29kbGUgfHwgW10pIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHdvLm5hbWUgPT09IF9kKSB7XG4gICAgICAgICAgICAgICAgICAgICAgc2VjdGlvbi5sYWJlbHMgPSBzLmxhYmVscyB8fCBbW11dO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIHNlY3Rpb24ubGFiZWxzWzBdWydwYWNrJ10gPSAnUGFja3MnO1xuICAgICAgICAgICAgICBzZWN0aW9uLmxhYmVsc1swXVsnY29udGVudCddID0gJ0V2YWx1YXRpb25zJztcbiAgICAgICAgICAgICAgc2VjdGlvbi5sYWJlbHNbMF1bJzcnXSA9ICdTY2FuIGxpc3RlbmluZyBuZXR3b3RrIHBvcnRzJztcbiAgICAgICAgICAgICAgc2VjdGlvbi50YWJzLnB1c2goZXF1aXZhbGVuY2VzW19kXSk7XG5cbiAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoY29uZmlnLmNvbmZpZ1tfZF0pKSB7XG4gICAgICAgICAgICAgICAgLyogTE9HIENPTExFQ1RPUiAqL1xuICAgICAgICAgICAgICAgIGlmIChfZCA9PT0gJ2xvY2FsZmlsZScpIHtcbiAgICAgICAgICAgICAgICAgIGxldCBncm91cHMgPSBbXTtcbiAgICAgICAgICAgICAgICAgIGNvbmZpZy5jb25maWdbX2RdLmZvckVhY2goKG9iaikgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIWdyb3Vwc1tvYmoubG9nZm9ybWF0XSkge1xuICAgICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XS5wdXNoKG9iaik7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKGdyb3VwcykuZm9yRWFjaCgoZ3JvdXApID0+IHtcbiAgICAgICAgICAgICAgICAgICAgbGV0IHNhdmVpZHggPSAwO1xuICAgICAgICAgICAgICAgICAgICBncm91cHNbZ3JvdXBdLmZvckVhY2goKHgsIGkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICBpZiAoT2JqZWN0LmtleXMoeCkubGVuZ3RoID4gT2JqZWN0LmtleXMoZ3JvdXBzW2dyb3VwXVtzYXZlaWR4XSkubGVuZ3RoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzYXZlaWR4ID0gaTtcbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBjb2x1bW5zID0gT2JqZWN0LmtleXMoZ3JvdXBzW2dyb3VwXVtzYXZlaWR4XSk7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IHJvd3MgPSBncm91cHNbZ3JvdXBdLm1hcCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgIGxldCByb3cgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGtleSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgcm93LnB1c2goXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHR5cGVvZiB4W2tleV0gIT09ICdvYmplY3QnXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPyB4W2tleV1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IEFycmF5LmlzQXJyYXkoeFtrZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgID8geFtrZXldLm1hcCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4geCArICdcXG4nO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IEpTT04uc3RyaW5naWZ5KHhba2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJvdztcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoY29sLCBpKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgY29sdW1uc1tpXSA9IGNvbFswXS50b1VwcGVyQ2FzZSgpICsgY29sLnNsaWNlKDEpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnTG9jYWwgZmlsZXMnLFxuICAgICAgICAgICAgICAgICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgICAgICAgICAgICAgICAgY29sdW1ucyxcbiAgICAgICAgICAgICAgICAgICAgICByb3dzLFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoX2QgPT09ICdsYWJlbHMnKSB7XG4gICAgICAgICAgICAgICAgICBjb25zdCBvYmogPSBjb25maWcuY29uZmlnW19kXVswXS5sYWJlbDtcbiAgICAgICAgICAgICAgICAgIGNvbnN0IGNvbHVtbnMgPSBPYmplY3Qua2V5cyhvYmpbMF0pO1xuICAgICAgICAgICAgICAgICAgaWYgKCFjb2x1bW5zLmluY2x1ZGVzKCdoaWRkZW4nKSkge1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLnB1c2goJ2hpZGRlbicpO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgY29uc3Qgcm93cyA9IG9iai5tYXAoKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGtleSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHhba2V5XSk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gcm93O1xuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGNvbCwgaSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zW2ldID0gY29sWzBdLnRvVXBwZXJDYXNlKCkgKyBjb2wuc2xpY2UoMSk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgdGl0bGU6ICdMYWJlbHMnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLFxuICAgICAgICAgICAgICAgICAgICByb3dzLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgIGZvciAobGV0IF9kMiBvZiBjb25maWcuY29uZmlnW19kXSkge1xuICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaCguLi50aGlzLmdldENvbmZpZ1RhYmxlcyhfZDIsIHNlY3Rpb24sIGlkeCkpO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAvKklOVEVHUklUWSBNT05JVE9SSU5HIE1PTklUT1JFRCBESVJFQ1RPUklFUyAqL1xuICAgICAgICAgICAgICAgIGlmIChjb25maWcuY29uZmlnW19kXS5kaXJlY3Rvcmllcykge1xuICAgICAgICAgICAgICAgICAgY29uc3QgZGlyZWN0b3JpZXMgPSBjb25maWcuY29uZmlnW19kXS5kaXJlY3RvcmllcztcbiAgICAgICAgICAgICAgICAgIGRlbGV0ZSBjb25maWcuY29uZmlnW19kXS5kaXJlY3RvcmllcztcbiAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKC4uLnRoaXMuZ2V0Q29uZmlnVGFibGVzKGNvbmZpZy5jb25maWdbX2RdLCBzZWN0aW9uLCBpZHgpKTtcbiAgICAgICAgICAgICAgICAgIGxldCBkaWZmT3B0cyA9IFtdO1xuICAgICAgICAgICAgICAgICAgT2JqZWN0LmtleXMoc2VjdGlvbi5vcHRzKS5mb3JFYWNoKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGRpZmZPcHRzLnB1c2goeCk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIGNvbnN0IGNvbHVtbnMgPSBbXG4gICAgICAgICAgICAgICAgICAgICcnLFxuICAgICAgICAgICAgICAgICAgICAuLi5kaWZmT3B0cy5maWx0ZXIoKHgpID0+IHggIT09ICdjaGVja19hbGwnICYmIHggIT09ICdjaGVja19zdW0nKSxcbiAgICAgICAgICAgICAgICAgIF07XG4gICAgICAgICAgICAgICAgICBsZXQgcm93cyA9IFtdO1xuICAgICAgICAgICAgICAgICAgZGlyZWN0b3JpZXMuZm9yRWFjaCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBsZXQgcm93ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgucGF0aCk7XG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoeSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgIGlmICh5ICE9PSAnJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgeSA9IHkgIT09ICdjaGVja193aG9kYXRhJyA/IHkgOiAnd2hvZGF0YSc7XG4gICAgICAgICAgICAgICAgICAgICAgICByb3cucHVzaCh4W3ldID8geFt5XSA6ICdubycpO1xuICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgucmVjdXJzaW9uX2xldmVsKTtcbiAgICAgICAgICAgICAgICAgICAgcm93cy5wdXNoKHJvdyk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoeCwgaWR4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnNbaWR4XSA9IHNlY3Rpb24ub3B0c1t4XTtcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKCdSTCcpO1xuICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ01vbml0b3JlZCBkaXJlY3RvcmllcycsXG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnMsXG4gICAgICAgICAgICAgICAgICAgIHJvd3MsXG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goLi4udGhpcy5nZXRDb25maWdUYWJsZXMoY29uZmlnLmNvbmZpZ1tfZF0sIHNlY3Rpb24sIGlkeCkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBmb3IgKGNvbnN0IHRhYmxlIG9mIHRhYmxlcykge1xuICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29uZmlnVGFibGVzKFt0YWJsZV0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlkeCsrO1xuICAgICAgICAgICAgICB0YWJsZXMgPSBbXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRhYmxlcyA9IFtdO1xuICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0EgY29uZmlndXJhdGlvbiBmb3IgdGhpcyBncm91cCBoYXMgbm90IHlldCBiZWVuIHNldCB1cC4nLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDEyLCBjb2xvcjogJyMwMDAnIH0sXG4gICAgICAgICAgICBtYXJnaW46IFswLCAxMCwgMCwgMTVdLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICBpZiAoY29tcG9uZW50c1snMSddKSB7XG4gICAgICAgIGxldCBhZ2VudHNJbkdyb3VwID0gW107XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgYWdlbnRzSW5Hcm91cFJlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgYC9ncm91cHMvJHtncm91cElEfS9hZ2VudHNgLFxuICAgICAgICAgICAge30sXG4gICAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICAgICk7XG4gICAgICAgICAgYWdlbnRzSW5Hcm91cCA9IGFnZW50c0luR3JvdXBSZXNwb25zZS5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXM7XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgbG9nKCdyZXBvcnRpbmc6cmVwb3J0JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgJ2RlYnVnJyk7XG4gICAgICAgIH1cbiAgICAgICAgYXdhaXQgdGhpcy5yZW5kZXJIZWFkZXIoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBwcmludGVyLFxuICAgICAgICAgICdncm91cENvbmZpZycsXG4gICAgICAgICAgZ3JvdXBJRCxcbiAgICAgICAgICAoYWdlbnRzSW5Hcm91cCB8fCBbXSkubWFwKCh4KSA9PiB4LmlkKSxcbiAgICAgICAgICBhcGlJZFxuICAgICAgICApO1xuICAgICAgfVxuXG4gICAgICBhd2FpdCBwcmludGVyLnByaW50KHBhdGguam9pbihXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILCB1c2VySUQsIG5hbWUpKTtcblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgICAgbWVzc2FnZTogYFJlcG9ydCAke25hbWV9IHdhcyBjcmVhdGVkYCxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzR3JvdXBzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA1MDI5LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogQ3JlYXRlIGEgcmVwb3J0IGZvciB0aGUgYWdlbnRzXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7Kn0gcmVwb3J0cyBsaXN0IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNyZWF0ZVJlcG9ydHNBZ2VudHMoXG4gICAgY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LFxuICAgIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsXG4gICAgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeVxuICApIHtcbiAgICB0cnkge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50cycsIGBSZXBvcnQgc3RhcnRlZGAsICdpbmZvJyk7XG4gICAgICBjb25zdCB7IGJyb3dzZXJUaW1lem9uZSwgc2VhcmNoQmFyLCBmaWx0ZXJzLCB0aW1lLCBuYW1lLCBjb21wb25lbnRzIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICBjb25zdCB7IGFnZW50SUQgfSA9IHJlcXVlc3QucGFyYW1zO1xuICAgICAgY29uc3QgeyBpZDogYXBpSWQgfSA9IHJlcXVlc3QuaGVhZGVycztcbiAgICAgIGNvbnN0IHsgZnJvbSwgdG8gfSA9IHRpbWUgfHwge307XG5cbiAgICAgIGNvbnN0IHByaW50ZXIgPSBuZXcgUmVwb3J0UHJpbnRlcigpO1xuXG4gICAgICBjb25zdCB7IHVzZXJuYW1lOiB1c2VySUQgfSA9IGF3YWl0IGNvbnRleHQud2F6dWguc2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCk7XG4gICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMocGF0aC5qb2luKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgsIHVzZXJJRCkpO1xuXG4gICAgICBsZXQgd21vZHVsZXNSZXNwb25zZSA9IHt9O1xuICAgICAgbGV0IHRhYmxlcyA9IFtdO1xuICAgICAgdHJ5IHtcbiAgICAgICAgd21vZHVsZXNSZXNwb25zZSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9hZ2VudHMvJHthZ2VudElEfS9jb25maWcvd21vZHVsZXMvd21vZHVsZXNgLFxuICAgICAgICAgIHt9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpyZXBvcnQnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAnZGVidWcnKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgdGhpcy5yZW5kZXJIZWFkZXIoY29udGV4dCwgcHJpbnRlciwgJ2FnZW50Q29uZmlnJywgJ2FnZW50Q29uZmlnJywgYWdlbnRJRCwgYXBpSWQpO1xuXG4gICAgICBsZXQgaWR4Q29tcG9uZW50ID0gMDtcbiAgICAgIGZvciAobGV0IGNvbmZpZyBvZiBBZ2VudENvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnMpIHtcbiAgICAgICAgbGV0IHRpdGxlT2ZTZWN0aW9uID0gZmFsc2U7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHMnLFxuICAgICAgICAgIGBJdGVyYXRlIG92ZXIgJHtjb25maWcuc2VjdGlvbnMubGVuZ3RofSBjb25maWd1cmF0aW9uIHNlY3Rpb25zYCxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICAgIGZvciAobGV0IHNlY3Rpb24gb2YgY29uZmlnLnNlY3Rpb25zKSB7XG4gICAgICAgICAgaWYgKGNvbXBvbmVudHNbaWR4Q29tcG9uZW50XSAmJiAoc2VjdGlvbi5jb25maWcgfHwgc2VjdGlvbi53b2RsZSkpIHtcbiAgICAgICAgICAgIGxldCBpZHggPSAwO1xuICAgICAgICAgICAgY29uc3QgY29uZmlncyA9IChzZWN0aW9uLmNvbmZpZyB8fCBbXSkuY29uY2F0KHNlY3Rpb24ud29kbGUgfHwgW10pO1xuICAgICAgICAgICAgbG9nKFxuICAgICAgICAgICAgICAncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHMnLFxuICAgICAgICAgICAgICBgSXRlcmF0ZSBvdmVyICR7Y29uZmlncy5sZW5ndGh9IGNvbmZpZ3VyYXRpb24gYmxvY2tzYCxcbiAgICAgICAgICAgICAgJ2RlYnVnJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIGZvciAobGV0IGNvbmYgb2YgY29uZmlncykge1xuICAgICAgICAgICAgICBsZXQgYWdlbnRDb25maWdSZXNwb25zZSA9IHt9O1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGlmICghY29uZlsnbmFtZSddKSB7XG4gICAgICAgICAgICAgICAgICBhZ2VudENvbmZpZ1Jlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICAgICAgICAgIGAvYWdlbnRzLyR7YWdlbnRJRH0vY29uZmlnLyR7Y29uZi5jb21wb25lbnR9LyR7Y29uZi5jb25maWd1cmF0aW9ufWAsXG4gICAgICAgICAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgZm9yIChsZXQgd29kbGUgb2Ygd21vZHVsZXNSZXNwb25zZS5kYXRhLmRhdGFbJ3dtb2R1bGVzJ10pIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKE9iamVjdC5rZXlzKHdvZGxlKVswXSA9PT0gY29uZlsnbmFtZSddKSB7XG4gICAgICAgICAgICAgICAgICAgICAgYWdlbnRDb25maWdSZXNwb25zZS5kYXRhID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgZGF0YTogd29kbGUsXG4gICAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGNvbnN0IGFnZW50Q29uZmlnID1cbiAgICAgICAgICAgICAgICAgIGFnZW50Q29uZmlnUmVzcG9uc2UgJiYgYWdlbnRDb25maWdSZXNwb25zZS5kYXRhICYmIGFnZW50Q29uZmlnUmVzcG9uc2UuZGF0YS5kYXRhO1xuICAgICAgICAgICAgICAgIGlmICghdGl0bGVPZlNlY3Rpb24pIHtcbiAgICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgICAgICAgIHRleHQ6IGNvbmZpZy50aXRsZSxcbiAgICAgICAgICAgICAgICAgICAgc3R5bGU6ICdoMScsXG4gICAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzAsIDAsIDAsIDE1XSxcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgdGl0bGVPZlNlY3Rpb24gPSB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgICAgICAgdGV4dDogc2VjdGlvbi5zdWJ0aXRsZSxcbiAgICAgICAgICAgICAgICAgIHN0eWxlOiAnaDQnLFxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgICAgICB0ZXh0OiBzZWN0aW9uLmRlc2MsXG4gICAgICAgICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMTIsIGNvbG9yOiAnIzAwMCcgfSxcbiAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzAsIDAsIDAsIDEwXSxcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICBpZiAoYWdlbnRDb25maWcpIHtcbiAgICAgICAgICAgICAgICAgIGZvciAobGV0IGFnZW50Q29uZmlnS2V5IG9mIE9iamVjdC5rZXlzKGFnZW50Q29uZmlnKSkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShhZ2VudENvbmZpZ1thZ2VudENvbmZpZ0tleV0pKSB7XG4gICAgICAgICAgICAgICAgICAgICAgLyogTE9HIENPTExFQ1RPUiAqL1xuICAgICAgICAgICAgICAgICAgICAgIGlmIChjb25mLmZpbHRlckJ5KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBsZXQgZ3JvdXBzID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICBhZ2VudENvbmZpZ1thZ2VudENvbmZpZ0tleV0uZm9yRWFjaCgob2JqKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZ3JvdXBzW29iai5sb2dmb3JtYXRdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZ3JvdXBzW29iai5sb2dmb3JtYXRdID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgZ3JvdXBzW29iai5sb2dmb3JtYXRdLnB1c2gob2JqKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmtleXMoZ3JvdXBzKS5mb3JFYWNoKChncm91cCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICBsZXQgc2F2ZWlkeCA9IDA7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tncm91cF0uZm9yRWFjaCgoeCwgaSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKHgpLmxlbmd0aCA+IE9iamVjdC5rZXlzKGdyb3Vwc1tncm91cF1bc2F2ZWlkeF0pLmxlbmd0aFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2F2ZWlkeCA9IGk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgY29sdW1ucyA9IE9iamVjdC5rZXlzKGdyb3Vwc1tncm91cF1bc2F2ZWlkeF0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCByb3dzID0gZ3JvdXBzW2dyb3VwXS5tYXAoKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsZXQgcm93ID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKChrZXkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0eXBlb2YgeFtrZXldICE9PSAnb2JqZWN0J1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgID8geFtrZXldXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiBBcnJheS5pc0FycmF5KHhba2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/IHhba2V5XS5tYXAoKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHggKyAnXFxuJztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiBKU09OLnN0cmluZ2lmeSh4W2tleV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByb3c7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGNvbCwgaSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnNbaV0gPSBjb2xbMF0udG9VcHBlckNhc2UoKSArIGNvbC5zbGljZSgxKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogc2VjdGlvbi5sYWJlbHNbMF1bZ3JvdXBdLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByb3dzLFxuICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoYWdlbnRDb25maWdLZXkuY29uZmlndXJhdGlvbiAhPT0gJ3NvY2tldCcpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi50aGlzLmdldENvbmZpZ1RhYmxlcyhhZ2VudENvbmZpZ1thZ2VudENvbmZpZ0tleV0sIHNlY3Rpb24sIGlkeClcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAobGV0IF9kMiBvZiBhZ2VudENvbmZpZ1thZ2VudENvbmZpZ0tleV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goLi4udGhpcy5nZXRDb25maWdUYWJsZXMoX2QyLCBzZWN0aW9uLCBpZHgpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgLypJTlRFR1JJVFkgTU9OSVRPUklORyBNT05JVE9SRUQgRElSRUNUT1JJRVMgKi9cbiAgICAgICAgICAgICAgICAgICAgICBpZiAoY29uZi5tYXRyaXgpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGRpcmVjdG9yaWVzID0gYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldLmRpcmVjdG9yaWVzO1xuICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIGFnZW50Q29uZmlnW2FnZW50Q29uZmlnS2V5XS5kaXJlY3RvcmllcztcbiAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi50aGlzLmdldENvbmZpZ1RhYmxlcyhhZ2VudENvbmZpZ1thZ2VudENvbmZpZ0tleV0sIHNlY3Rpb24sIGlkeClcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICBsZXQgZGlmZk9wdHMgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKHNlY3Rpb24ub3B0cykuZm9yRWFjaCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICBkaWZmT3B0cy5wdXNoKHgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBjb2x1bW5zID0gW1xuICAgICAgICAgICAgICAgICAgICAgICAgICAnJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uZGlmZk9wdHMuZmlsdGVyKCh4KSA9PiB4ICE9PSAnY2hlY2tfYWxsJyAmJiB4ICE9PSAnY2hlY2tfc3VtJyksXG4gICAgICAgICAgICAgICAgICAgICAgICBdO1xuICAgICAgICAgICAgICAgICAgICAgICAgbGV0IHJvd3MgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGRpcmVjdG9yaWVzLmZvckVhY2goKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICByb3cucHVzaCh4LmRpcik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoeSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICh5ICE9PSAnJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm93LnB1c2goeC5vcHRzLmluZGV4T2YoeSkgPiAtMSA/ICd5ZXMnIDogJ25vJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgcm93LnB1c2goeC5yZWN1cnNpb25fbGV2ZWwpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICByb3dzLnB1c2gocm93KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKCh4LCBpZHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1uc1tpZHhdID0gc2VjdGlvbi5vcHRzW3hdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLnB1c2goJ1JMJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnTW9uaXRvcmVkIGRpcmVjdG9yaWVzJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgcm93cyxcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgLi4udGhpcy5nZXRDb25maWdUYWJsZXMoYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldLCBzZWN0aW9uLCBpZHgpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAvLyBQcmludCBubyBjb25maWd1cmVkIG1vZHVsZSBhbmQgbGluayB0byB0aGUgZG9jdW1lbnRhdGlvblxuICAgICAgICAgICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgICAgICAgICAgdGV4dDogW1xuICAgICAgICAgICAgICAgICAgICAgICdUaGlzIG1vZHVsZSBpcyBub3QgY29uZmlndXJlZC4gUGxlYXNlIHRha2UgYSBsb29rIG9uIGhvdyB0byBjb25maWd1cmUgaXQgaW4gJyxcbiAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBgJHtzZWN0aW9uLnN1YnRpdGxlLnRvTG93ZXJDYXNlKCl9IGNvbmZpZ3VyYXRpb24uYCxcbiAgICAgICAgICAgICAgICAgICAgICAgIGxpbms6IHNlY3Rpb24uZG9jdUxpbmssXG4gICAgICAgICAgICAgICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMTIsIGNvbG9yOiAnIzFhMGRhYicgfSxcbiAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgICAgICAgICBtYXJnaW46IFswLCAwLCAwLCAyMF0sXG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgbG9nKCdyZXBvcnRpbmc6cmVwb3J0JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgJ2RlYnVnJyk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgaWR4Kys7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBmb3IgKGNvbnN0IHRhYmxlIG9mIHRhYmxlcykge1xuICAgICAgICAgICAgICBwcmludGVyLmFkZENvbmZpZ1RhYmxlcyhbdGFibGVdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgaWR4Q29tcG9uZW50Kys7XG4gICAgICAgICAgdGFibGVzID0gW107XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgYXdhaXQgcHJpbnRlci5wcmludChwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgdXNlcklELCBuYW1lKSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIG1lc3NhZ2U6IGBSZXBvcnQgJHtuYW1lfSB3YXMgY3JlYXRlZGAsXG4gICAgICAgIH0sXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAyOSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIENyZWF0ZSBhIHJlcG9ydCBmb3IgdGhlIGFnZW50c1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMgeyp9IHJlcG9ydHMgbGlzdCBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjcmVhdGVSZXBvcnRzQWdlbnRzSW52ZW50b3J5KFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LFxuICAgIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnlcbiAgKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnknLCBgUmVwb3J0IHN0YXJ0ZWRgLCAnaW5mbycpO1xuICAgICAgY29uc3QgeyBicm93c2VyVGltZXpvbmUsIHNlYXJjaEJhciwgZmlsdGVycywgdGltZSwgbmFtZSB9ID0gcmVxdWVzdC5ib2R5O1xuICAgICAgY29uc3QgeyBhZ2VudElEIH0gPSByZXF1ZXN0LnBhcmFtcztcbiAgICAgIGNvbnN0IHsgaWQ6IGFwaUlkLCBwYXR0ZXJuOiBpbmRleFBhdHRlcm4gfSA9IHJlcXVlc3QuaGVhZGVycztcbiAgICAgIGNvbnN0IHsgZnJvbSwgdG8gfSA9IHRpbWUgfHwge307XG4gICAgICAvLyBJbml0XG4gICAgICBjb25zdCBwcmludGVyID0gbmV3IFJlcG9ydFByaW50ZXIoKTtcblxuICAgICAgY29uc3QgeyB1c2VybmFtZTogdXNlcklEIH0gPSBhd2FpdCBjb250ZXh0LndhenVoLnNlY3VyaXR5LmdldEN1cnJlbnRVc2VyKHJlcXVlc3QsIGNvbnRleHQpO1xuICAgICAgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzKCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhXQVpVSF9EQVRBX0RPV05MT0FEU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKHBhdGguam9pbihXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILCB1c2VySUQpKTtcblxuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50c0ludmVudG9yeScsIGBTeXNjb2xsZWN0b3IgcmVwb3J0YCwgJ2RlYnVnJyk7XG4gICAgICBjb25zdCBzYW5pdGl6ZWRGaWx0ZXJzID0gZmlsdGVycyA/IHRoaXMuc2FuaXRpemVLaWJhbmFGaWx0ZXJzKGZpbHRlcnMsIHNlYXJjaEJhcikgOiBmYWxzZTtcblxuICAgICAgLy8gR2V0IHRoZSBhZ2VudCBPU1xuICAgICAgbGV0IGFnZW50T3MgPSAnJztcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGFnZW50UmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICcvYWdlbnRzJyxcbiAgICAgICAgICB7IHBhcmFtczogeyBxOiBgaWQ9JHthZ2VudElEfWAgfSB9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICAgIGFnZW50T3MgPSBhZ2VudFJlc3BvbnNlLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXS5vcy5wbGF0Zm9ybTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnknLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAnZGVidWcnKTtcbiAgICAgIH1cblxuICAgICAgLy8gQWRkIHRpdGxlXG4gICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgIHRleHQ6ICdJbnZlbnRvcnkgZGF0YSByZXBvcnQnLFxuICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgIH0pO1xuXG4gICAgICAvLyBBZGQgdGFibGUgd2l0aCB0aGUgYWdlbnQgaW5mb1xuICAgICAgYXdhaXQgdGhpcy5idWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIFthZ2VudElEXSwgYXBpSWQpO1xuXG4gICAgICAvLyBHZXQgc3lzY29sbGVjdG9yIHBhY2thZ2VzIGFuZCBwcm9jZXNzZXNcbiAgICAgIGNvbnN0IGFnZW50UmVxdWVzdHNJbnZlbnRvcnkgPSBbXG4gICAgICAgIHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9wYWNrYWdlc2AsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIHBhY2thZ2VzIGZvciBhZ2VudCAke2FnZW50SUR9YCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgdGl0bGU6ICdQYWNrYWdlcycsXG4gICAgICAgICAgICBjb2x1bW5zOlxuICAgICAgICAgICAgICBhZ2VudE9zID09PSAnd2luZG93cydcbiAgICAgICAgICAgICAgICA/IFtcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ25hbWUnLCBsYWJlbDogJ05hbWUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdhcmNoaXRlY3R1cmUnLCBsYWJlbDogJ0FyY2hpdGVjdHVyZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3ZlcnNpb24nLCBsYWJlbDogJ1ZlcnNpb24nIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICd2ZW5kb3InLCBsYWJlbDogJ1ZlbmRvcicgfSxcbiAgICAgICAgICAgICAgICAgIF1cbiAgICAgICAgICAgICAgICA6IFtcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ25hbWUnLCBsYWJlbDogJ05hbWUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdhcmNoaXRlY3R1cmUnLCBsYWJlbDogJ0FyY2hpdGVjdHVyZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3ZlcnNpb24nLCBsYWJlbDogJ1ZlcnNpb24nIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICd2ZW5kb3InLCBsYWJlbDogJ1ZlbmRvcicgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2Rlc2NyaXB0aW9uJywgbGFiZWw6ICdEZXNjcmlwdGlvbicgfSxcbiAgICAgICAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIGVuZHBvaW50OiBgL3N5c2NvbGxlY3Rvci8ke2FnZW50SUR9L3Byb2Nlc3Nlc2AsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIHByb2Nlc3NlcyBmb3IgYWdlbnQgJHthZ2VudElEfWAsXG4gICAgICAgICAgdGFibGU6IHtcbiAgICAgICAgICAgIHRpdGxlOiAnUHJvY2Vzc2VzJyxcbiAgICAgICAgICAgIGNvbHVtbnM6XG4gICAgICAgICAgICAgIGFnZW50T3MgPT09ICd3aW5kb3dzJ1xuICAgICAgICAgICAgICAgID8gW1xuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbmFtZScsIGxhYmVsOiAnTmFtZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2NtZCcsIGxhYmVsOiAnQ01EJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAncHJpb3JpdHknLCBsYWJlbDogJ1ByaW9yaXR5JyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbmx3cCcsIGxhYmVsOiAnTkxXUCcgfSxcbiAgICAgICAgICAgICAgICAgIF1cbiAgICAgICAgICAgICAgICA6IFtcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ25hbWUnLCBsYWJlbDogJ05hbWUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdldXNlcicsIGxhYmVsOiAnRWZmZWN0aXZlIHVzZXInIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICduaWNlJywgbGFiZWw6ICdQcmlvcml0eScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3N0YXRlJywgbGFiZWw6ICdTdGF0ZScgfSxcbiAgICAgICAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBtYXBSZXNwb25zZUl0ZW1zOiAoaXRlbSkgPT5cbiAgICAgICAgICAgIGFnZW50T3MgPT09ICd3aW5kb3dzJyA/IGl0ZW0gOiB7IC4uLml0ZW0sIHN0YXRlOiBQcm9jZXNzRXF1aXZhbGVuY2VbaXRlbS5zdGF0ZV0gfSxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIGVuZHBvaW50OiBgL3N5c2NvbGxlY3Rvci8ke2FnZW50SUR9L3BvcnRzYCxcbiAgICAgICAgICBsb2dnZXJNZXNzYWdlOiBgRmV0Y2hpbmcgcG9ydHMgZm9yIGFnZW50ICR7YWdlbnRJRH1gLFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICB0aXRsZTogJ05ldHdvcmsgcG9ydHMnLFxuICAgICAgICAgICAgY29sdW1uczpcbiAgICAgICAgICAgICAgYWdlbnRPcyA9PT0gJ3dpbmRvd3MnXG4gICAgICAgICAgICAgICAgPyBbXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdsb2NhbF9pcCcsIGxhYmVsOiAnTG9jYWwgSVAnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdsb2NhbF9wb3J0JywgbGFiZWw6ICdMb2NhbCBwb3J0JyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAncHJvY2VzcycsIGxhYmVsOiAnUHJvY2VzcycgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3N0YXRlJywgbGFiZWw6ICdTdGF0ZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3Byb3RvY29sJywgbGFiZWw6ICdQcm90b2NvbCcgfSxcbiAgICAgICAgICAgICAgICAgIF1cbiAgICAgICAgICAgICAgICA6IFtcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2xvY2FsX2lwJywgbGFiZWw6ICdMb2NhbCBJUCcgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2xvY2FsX3BvcnQnLCBsYWJlbDogJ0xvY2FsIHBvcnQnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdzdGF0ZScsIGxhYmVsOiAnU3RhdGUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdwcm90b2NvbCcsIGxhYmVsOiAnUHJvdG9jb2wnIH0sXG4gICAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgbWFwUmVzcG9uc2VJdGVtczogKGl0ZW0pID0+ICh7XG4gICAgICAgICAgICAuLi5pdGVtLFxuICAgICAgICAgICAgbG9jYWxfaXA6IGl0ZW0ubG9jYWwuaXAsXG4gICAgICAgICAgICBsb2NhbF9wb3J0OiBpdGVtLmxvY2FsLnBvcnQsXG4gICAgICAgICAgfSksXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9uZXRpZmFjZWAsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIG5ldGlmYWNlIGZvciBhZ2VudCAke2FnZW50SUR9YCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgdGl0bGU6ICdOZXR3b3JrIGludGVyZmFjZXMnLFxuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAnbmFtZScsIGxhYmVsOiAnTmFtZScgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ21hYycsIGxhYmVsOiAnTWFjJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnc3RhdGUnLCBsYWJlbDogJ1N0YXRlJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnbXR1JywgbGFiZWw6ICdNVFUnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICd0eXBlJywgbGFiZWw6ICdUeXBlJyB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgZW5kcG9pbnQ6IGAvc3lzY29sbGVjdG9yLyR7YWdlbnRJRH0vbmV0YWRkcmAsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIG5ldGFkZHIgZm9yIGFnZW50ICR7YWdlbnRJRH1gLFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICB0aXRsZTogJ05ldHdvcmsgc2V0dGluZ3MnLFxuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAnaWZhY2UnLCBsYWJlbDogJ0ludGVyZmFjZScgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ2FkZHJlc3MnLCBsYWJlbDogJ2FkZHJlc3MnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICduZXRtYXNrJywgbGFiZWw6ICdOZXRtYXNrJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAncHJvdG8nLCBsYWJlbDogJ1Byb3RvY29sJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnYnJvYWRjYXN0JywgbGFiZWw6ICdCcm9hZGNhc3QnIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICBdO1xuXG4gICAgICBhZ2VudE9zID09PSAnd2luZG93cycgJiZcbiAgICAgICAgYWdlbnRSZXF1ZXN0c0ludmVudG9yeS5wdXNoKHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9ob3RmaXhlc2AsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIGhvdGZpeGVzIGZvciBhZ2VudCAke2FnZW50SUR9YCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgdGl0bGU6ICdXaW5kb3dzIHVwZGF0ZXMnLFxuICAgICAgICAgICAgY29sdW1uczogW3sgaWQ6ICdob3RmaXgnLCBsYWJlbDogJ1VwZGF0ZSBjb2RlJyB9XSxcbiAgICAgICAgICB9LFxuICAgICAgICB9KTtcblxuICAgICAgY29uc3QgcmVxdWVzdEludmVudG9yeSA9IGFzeW5jIChhZ2VudFJlcXVlc3RJbnZlbnRvcnkpID0+IHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBsb2coXG4gICAgICAgICAgICAncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnknLFxuICAgICAgICAgICAgYWdlbnRSZXF1ZXN0SW52ZW50b3J5LmxvZ2dlck1lc3NhZ2UsXG4gICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgKTtcblxuICAgICAgICAgIGNvbnN0IGludmVudG9yeVJlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgYWdlbnRSZXF1ZXN0SW52ZW50b3J5LmVuZHBvaW50LFxuICAgICAgICAgICAge30sXG4gICAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICAgICk7XG5cbiAgICAgICAgICBjb25zdCBpbnZlbnRvcnkgPVxuICAgICAgICAgICAgaW52ZW50b3J5UmVzcG9uc2UgJiZcbiAgICAgICAgICAgIGludmVudG9yeVJlc3BvbnNlLmRhdGEgJiZcbiAgICAgICAgICAgIGludmVudG9yeVJlc3BvbnNlLmRhdGEuZGF0YSAmJlxuICAgICAgICAgICAgaW52ZW50b3J5UmVzcG9uc2UuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zO1xuICAgICAgICAgIGlmIChpbnZlbnRvcnkpIHtcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgIC4uLmFnZW50UmVxdWVzdEludmVudG9yeS50YWJsZSxcbiAgICAgICAgICAgICAgaXRlbXM6IGFnZW50UmVxdWVzdEludmVudG9yeS5tYXBSZXNwb25zZUl0ZW1zXG4gICAgICAgICAgICAgICAgPyBpbnZlbnRvcnkubWFwKGFnZW50UmVxdWVzdEludmVudG9yeS5tYXBSZXNwb25zZUl0ZW1zKVxuICAgICAgICAgICAgICAgIDogaW52ZW50b3J5LFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50c0ludmVudG9yeScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsICdkZWJ1ZycpO1xuICAgICAgICB9XG4gICAgICB9O1xuXG4gICAgICBpZiAodGltZSkge1xuICAgICAgICBhd2FpdCB0aGlzLmV4dGVuZGVkSW5mb3JtYXRpb24oXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBwcmludGVyLFxuICAgICAgICAgICdhZ2VudHMnLFxuICAgICAgICAgICdzeXNjb2xsZWN0b3InLFxuICAgICAgICAgIGFwaUlkLFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgc2FuaXRpemVkRmlsdGVycyArICcgQU5EIHJ1bGUuZ3JvdXBzOiBcInZ1bG5lcmFiaWxpdHktZGV0ZWN0b3JcIicsXG4gICAgICAgICAgaW5kZXhQYXR0ZXJuLFxuICAgICAgICAgIGFnZW50SURcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgLy8gQWRkIGludmVudG9yeSB0YWJsZXNcbiAgICAgIChhd2FpdCBQcm9taXNlLmFsbChhZ2VudFJlcXVlc3RzSW52ZW50b3J5Lm1hcChyZXF1ZXN0SW52ZW50b3J5KSkpXG4gICAgICAgIC5maWx0ZXIoKHRhYmxlKSA9PiB0YWJsZSlcbiAgICAgICAgLmZvckVhY2goKHRhYmxlKSA9PiBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHRhYmxlKSk7XG5cbiAgICAgIC8vIFByaW50IHRoZSBkb2N1bWVudFxuICAgICAgYXdhaXQgcHJpbnRlci5wcmludChwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgdXNlcklELCBuYW1lKSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIG1lc3NhZ2U6IGBSZXBvcnQgJHtuYW1lfSB3YXMgY3JlYXRlZGAsXG4gICAgICAgIH0sXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAyOSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIEZldGNoIHRoZSByZXBvcnRzIGxpc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtBcnJheTxPYmplY3Q+fSByZXBvcnRzIGxpc3Qgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0UmVwb3J0cyhcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogS2liYW5hUmVxdWVzdCxcbiAgICByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5XG4gICkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpnZXRSZXBvcnRzJywgYEZldGNoaW5nIGNyZWF0ZWQgcmVwb3J0c2AsICdpbmZvJyk7XG4gICAgICBjb25zdCB7IHVzZXJuYW1lOiB1c2VySUQgfSA9IGF3YWl0IGNvbnRleHQud2F6dWguc2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCk7XG4gICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY29uc3QgdXNlclJlcG9ydHNEaXJlY3RvcnkgPSBwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgdXNlcklEKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKHVzZXJSZXBvcnRzRGlyZWN0b3J5KTtcbiAgICAgIGxvZygncmVwb3J0aW5nOmdldFJlcG9ydHMnLCBgRGlyZWN0b3J5OiAke3VzZXJSZXBvcnRzRGlyZWN0b3J5fWAsICdkZWJ1ZycpO1xuXG4gICAgICBjb25zdCBzb3J0UmVwb3J0c0J5RGF0ZSA9IChhLCBiKSA9PiAoYS5kYXRlIDwgYi5kYXRlID8gMSA6IGEuZGF0ZSA+IGIuZGF0ZSA/IC0xIDogMCk7XG5cbiAgICAgIGNvbnN0IHJlcG9ydHMgPSBmcy5yZWFkZGlyU3luYyh1c2VyUmVwb3J0c0RpcmVjdG9yeSkubWFwKChmaWxlKSA9PiB7XG4gICAgICAgIGNvbnN0IHN0YXRzID0gZnMuc3RhdFN5bmModXNlclJlcG9ydHNEaXJlY3RvcnkgKyAnLycgKyBmaWxlKTtcbiAgICAgICAgLy8gR2V0IHRoZSBmaWxlIGNyZWF0aW9uIHRpbWUgKGJpdGh0aW1lKS4gSXQgcmV0dXJucyB0aGUgZmlyc3QgdmFsdWUgdGhhdCBpcyBhIHRydXRoeSB2YWx1ZSBvZiBuZXh0IGZpbGUgc3RhdHM6IGJpcnRodGltZSwgbXRpbWUsIGN0aW1lIGFuZCBhdGltZS5cbiAgICAgICAgLy8gVGhpcyBzb2x2ZXMgc29tZSBPU3MgY2FuIGhhdmUgdGhlIGJpdGh0aW1lTXMgZXF1YWwgdG8gMCBhbmQgcmV0dXJucyB0aGUgZGF0ZSBsaWtlIDE5NzAtMDEtMDFcbiAgICAgICAgY29uc3QgYmlydGhUaW1lRmllbGQgPSBbJ2JpcnRodGltZScsICdtdGltZScsICdjdGltZScsICdhdGltZSddLmZpbmQoXG4gICAgICAgICAgKHRpbWUpID0+IHN0YXRzW2Ake3RpbWV9TXNgXVxuICAgICAgICApO1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIG5hbWU6IGZpbGUsXG4gICAgICAgICAgc2l6ZTogc3RhdHMuc2l6ZSxcbiAgICAgICAgICBkYXRlOiBzdGF0c1tiaXJ0aFRpbWVGaWVsZF0sXG4gICAgICAgIH07XG4gICAgICB9KTtcbiAgICAgIGxvZygncmVwb3J0aW5nOmdldFJlcG9ydHMnLCBgVXNpbmcgVGltU29ydCBmb3Igc29ydGluZyAke3JlcG9ydHMubGVuZ3RofSBpdGVtc2AsICdkZWJ1ZycpO1xuICAgICAgVGltU29ydC5zb3J0KHJlcG9ydHMsIHNvcnRSZXBvcnRzQnlEYXRlKTtcbiAgICAgIGxvZygncmVwb3J0aW5nOmdldFJlcG9ydHMnLCBgVG90YWwgcmVwb3J0czogJHtyZXBvcnRzLmxlbmd0aH1gLCAnZGVidWcnKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgcmVwb3J0cyB9LFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmdldFJlcG9ydHMnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDUwMzEsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBGZXRjaCBzcGVjaWZpYyByZXBvcnRcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IHJlcG9ydCBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBnZXRSZXBvcnRCeU5hbWUoXG4gICAgY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LFxuICAgIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsXG4gICAgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeVxuICApIHtcbiAgICB0cnkge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0QnlOYW1lJywgYEdldHRpbmcgJHtyZXF1ZXN0LnBhcmFtcy5uYW1lfSByZXBvcnRgLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHsgdXNlcm5hbWU6IHVzZXJJRCB9ID0gYXdhaXQgY29udGV4dC53YXp1aC5zZWN1cml0eS5nZXRDdXJyZW50VXNlcihyZXF1ZXN0LCBjb250ZXh0KTtcbiAgICAgIGNvbnN0IHJlcG9ydEZpbGVCdWZmZXIgPSBmcy5yZWFkRmlsZVN5bmMoXG4gICAgICAgIHBhdGguam9pbihXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILCB1c2VySUQsIHJlcXVlc3QucGFyYW1zLm5hbWUpXG4gICAgICApO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL3BkZicgfSxcbiAgICAgICAgYm9keTogcmVwb3J0RmlsZUJ1ZmZlcixcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpnZXRSZXBvcnRCeU5hbWUnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDUwMzAsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBEZWxldGUgc3BlY2lmaWMgcmVwb3J0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBzdGF0dXMgb2JqIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGRlbGV0ZVJlcG9ydEJ5TmFtZShcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogS2liYW5hUmVxdWVzdCxcbiAgICByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5XG4gICkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpkZWxldGVSZXBvcnRCeU5hbWUnLCBgRGVsZXRpbmcgJHtyZXF1ZXN0LnBhcmFtcy5uYW1lfSByZXBvcnRgLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHsgdXNlcm5hbWU6IHVzZXJJRCB9ID0gYXdhaXQgY29udGV4dC53YXp1aC5zZWN1cml0eS5nZXRDdXJyZW50VXNlcihyZXF1ZXN0LCBjb250ZXh0KTtcbiAgICAgIGZzLnVubGlua1N5bmMoXG4gICAgICAgIHBhdGguam9pbihXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILCB1c2VySUQsIHJlcXVlc3QucGFyYW1zLm5hbWUpXG4gICAgICApO1xuICAgICAgbG9nKCdyZXBvcnRpbmc6ZGVsZXRlUmVwb3J0QnlOYW1lJywgYCR7cmVxdWVzdC5wYXJhbXMubmFtZX0gcmVwb3J0IHdhcyBkZWxldGVkYCwgJ2luZm8nKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgZXJyb3I6IDAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpkZWxldGVSZXBvcnRCeU5hbWUnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDUwMzIsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxufVxuIl19