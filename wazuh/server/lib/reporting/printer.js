"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ReportPrinter = void 0;

var _fs = _interopRequireDefault(require("fs"));

var _path = _interopRequireDefault(require("path"));

var _printer = _interopRequireDefault(require("pdfmake/src/printer"));

var _clockIconRaw = _interopRequireDefault(require("./clock-icon-raw"));

var _filterIconRaw = _interopRequireDefault(require("./filter-icon-raw"));

var _visualizations = require("../../integration-files/visualizations");

var _logger = require("../logger");

var TimSort = _interopRequireWildcard(require("timsort"));

function _getRequireWildcardCache() { if (typeof WeakMap !== "function") return null; var cache = new WeakMap(); _getRequireWildcardCache = function () { return cache; }; return cache; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const COLORS = {
  PRIMARY: '#00a9e5'
};
const pageConfiguration = {
  styles: {
    h1: {
      fontSize: 22,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h2: {
      fontSize: 18,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h3: {
      fontSize: 16,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h4: {
      fontSize: 14,
      monslight: true,
      color: COLORS.PRIMARY
    },
    standard: {
      color: '#333'
    },
    whiteColorFilters: {
      color: '#FFF',
      fontSize: 14
    },
    whiteColor: {
      color: '#FFF'
    }
  },
  pageMargins: [40, 80, 40, 80],
  header: {
    margin: [40, 20, 0, 0],
    columns: [{
      image: _path.default.join(__dirname, '../../../public/assets/logo.png'),
      width: 190
    }, {
      text: 'info@wazuh.com\nhttps://wazuh.com',
      alignment: 'right',
      margin: [0, 0, 40, 0],
      color: COLORS.PRIMARY
    }]
  },
  content: [],

  footer(currentPage, pageCount) {
    return {
      columns: [{
        text: 'Copyright © 2021 Wazuh, Inc.',
        color: COLORS.PRIMARY,
        margin: [40, 40, 0, 0]
      }, {
        text: 'Page ' + currentPage.toString() + ' of ' + pageCount,
        alignment: 'right',
        margin: [0, 40, 40, 0],
        color: COLORS.PRIMARY
      }]
    };
  },

  pageBreakBefore(currentNode, followingNodesOnPage) {
    if (currentNode.id && currentNode.id.includes('splitvis')) {
      return followingNodesOnPage.length === 6 || followingNodesOnPage.length === 7;
    }

    if (currentNode.id && currentNode.id.includes('splitsinglevis') || currentNode.id && currentNode.id.includes('singlevis')) {
      return followingNodesOnPage.length === 6;
    }

    return false;
  }

};
const fonts = {
  Roboto: {
    normal: _path.default.join(__dirname, '../../../public/assets/opensans/OpenSans-Light.ttf'),
    bold: _path.default.join(__dirname, '../../../public/assets/opensans/OpenSans-Bold.ttf'),
    italics: _path.default.join(__dirname, '../../../public/assets/opensans/OpenSans-Italic.ttf'),
    bolditalics: _path.default.join(__dirname, '../../../public/assets/opensans/OpenSans-BoldItalic.ttf'),
    monslight: _path.default.join(__dirname, '../../../public/assets/opensans/Montserrat-Light.ttf')
  }
};

class ReportPrinter {
  constructor() {
    _defineProperty(this, "_content", void 0);

    _defineProperty(this, "_printer", void 0);

    this._printer = new _printer.default(fonts);
    this._content = [];
  }

  addContent(...content) {
    this._content.push(...content);

    return this;
  }

  addConfigTables(tables) {
    (0, _logger.log)('reporting:renderConfigTables', 'Started to render configuration tables', 'info');
    (0, _logger.log)('reporting:renderConfigTables', `tables: ${tables.length}`, 'debug');

    for (const table of tables) {
      let rowsparsed = table.rows;

      if (Array.isArray(rowsparsed) && rowsparsed.length) {
        const rows = rowsparsed.length > 100 ? rowsparsed.slice(0, 99) : rowsparsed;
        this.addContent({
          text: table.title,
          style: {
            fontSize: 11,
            color: '#000'
          },
          margin: table.title && table.type === 'table' ? [0, 0, 0, 5] : ''
        });

        if (table.title === 'Monitored directories') {
          this.addContent({
            text: 'RT: Real time | WD: Who-data | Per.: Permission | MT: Modification time | SL: Symbolic link | RL: Recursion level',
            style: {
              fontSize: 8,
              color: COLORS.PRIMARY
            },
            margin: [0, 0, 0, 5]
          });
        }

        const full_body = [];
        const modifiedRows = rows.map(row => row.map(cell => ({
          text: cell || '-',
          style: 'standard'
        }))); // for (const row of rows) {
        //   modifiedRows.push(
        //     row.map(cell => ({ text: cell || '-', style: 'standard' }))
        //   );
        // }

        let widths = [];
        widths = Array(table.columns.length - 1).fill('auto');
        widths.push('*');

        if (table.type === 'config') {
          full_body.push(table.columns.map(col => ({
            text: col || '-',
            border: [0, 0, 0, 20],
            fontSize: 0,
            colSpan: 2
          })), ...modifiedRows);
          this.addContent({
            fontSize: 8,
            table: {
              headerRows: 0,
              widths,
              body: full_body,
              dontBreakRows: true
            },
            layout: {
              fillColor: i => i === 0 ? '#fff' : null,
              hLineColor: () => '#D3DAE6',
              hLineWidth: () => 1,
              vLineWidth: () => 0
            }
          });
        } else if (table.type === 'table') {
          full_body.push(table.columns.map(col => ({
            text: col || '-',
            style: 'whiteColor',
            border: [0, 0, 0, 0]
          })), ...modifiedRows);
          this.addContent({
            fontSize: 8,
            table: {
              headerRows: 1,
              widths,
              body: full_body
            },
            layout: {
              fillColor: i => i === 0 ? COLORS.PRIMARY : null,
              hLineColor: () => COLORS.PRIMARY,
              hLineWidth: () => 1,
              vLineWidth: () => 0
            }
          });
        }

        this.addNewLine();
      }

      (0, _logger.log)('reporting:renderConfigTables', `Table rendered`, 'debug');
    }
  }

  addTables(tables) {
    (0, _logger.log)('reporting:renderTables', 'Started to render tables', 'info');
    (0, _logger.log)('reporting:renderTables', `tables: ${tables.length}`, 'debug');

    for (const table of tables) {
      let rowsparsed = [];
      rowsparsed = table.rows;

      if (Array.isArray(rowsparsed) && rowsparsed.length) {
        const rows = rowsparsed.length > 100 ? rowsparsed.slice(0, 99) : rowsparsed;
        this.addContent({
          text: table.title,
          style: 'h3',
          pageBreak: 'before'
        });
        this.addNewLine();
        const full_body = [];

        const sortTableRows = (a, b) => parseInt(a[a.length - 1]) < parseInt(b[b.length - 1]) ? 1 : parseInt(a[a.length - 1]) > parseInt(b[b.length - 1]) ? -1 : 0;

        TimSort.sort(rows, sortTableRows);
        const modifiedRows = rows.map(row => row.map(cell => ({
          text: cell || '-',
          style: 'standard'
        })));
        const widths = Array(table.columns.length - 1).fill('auto');
        widths.push('*');
        full_body.push(table.columns.map(col => ({
          text: col || '-',
          style: 'whiteColor',
          border: [0, 0, 0, 0]
        })), ...modifiedRows);
        this.addContent({
          fontSize: 8,
          table: {
            headerRows: 1,
            widths,
            body: full_body
          },
          layout: {
            fillColor: i => i === 0 ? COLORS.PRIMARY : null,
            hLineColor: () => COLORS.PRIMARY,
            hLineWidth: () => 1,
            vLineWidth: () => 0
          }
        });
        this.addNewLine();
        (0, _logger.log)('reporting:renderTables', `Table rendered`, 'debug');
      }
    }
  }

  addTimeRangeAndFilters(from, to, filters, timeZone) {
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', `Started to render the time range and the filters`, 'info');
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', `from: ${from}, to: ${to}, filters: ${filters}, timeZone: ${timeZone}`, 'debug');
    const fromDate = new Date(new Date(from).toLocaleString('en-US', {
      timeZone
    }));
    const toDate = new Date(new Date(to).toLocaleString('en-US', {
      timeZone
    }));
    const str = `${this.formatDate(fromDate)} to ${this.formatDate(toDate)}`;
    this.addContent({
      fontSize: 8,
      table: {
        widths: ['*'],
        body: [[{
          columns: [{
            svg: _clockIconRaw.default,
            width: 10,
            height: 10,
            margin: [40, 5, 0, 0]
          }, {
            text: str || '-',
            margin: [43, 0, 0, 0],
            style: 'whiteColorFilters'
          }]
        }], [{
          columns: [{
            svg: _filterIconRaw.default,
            width: 10,
            height: 10,
            margin: [40, 6, 0, 0]
          }, {
            text: filters || '-',
            margin: [43, 0, 0, 0],
            style: 'whiteColorFilters'
          }]
        }]]
      },
      margin: [-40, 0, -40, 0],
      layout: {
        fillColor: () => COLORS.PRIMARY,
        hLineWidth: () => 0,
        vLineWidth: () => 0
      }
    });
    this.addContent({
      text: '\n'
    });
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', 'Time range and filters rendered', 'debug');
  }

  addVisualizations(visualizations, isAgents, tab) {
    (0, _logger.log)('reporting:renderVisualizations', `${visualizations.length} visualizations for tab ${tab}`, 'info');
    const single_vis = visualizations.filter(item => item.width >= 600);
    const double_vis = visualizations.filter(item => item.width < 600);
    single_vis.forEach(visualization => {
      const title = this.checkTitle(visualization, isAgents, tab);
      this.addContent({
        id: 'singlevis' + title[0]._source.title,
        text: title[0]._source.title,
        style: 'h3'
      });
      this.addContent({
        columns: [{
          image: visualization.element,
          width: 500
        }]
      });
      this.addNewLine();
    });
    let pair = [];

    for (const item of double_vis) {
      pair.push(item);

      if (pair.length === 2) {
        const title_1 = this.checkTitle(pair[0], isAgents, tab);
        const title_2 = this.checkTitle(pair[1], isAgents, tab);
        this.addContent({
          columns: [{
            id: 'splitvis' + title_1[0]._source.title,
            text: title_1[0]._source.title,
            style: 'h3',
            width: 280
          }, {
            id: 'splitvis' + title_2[0]._source.title,
            text: title_2[0]._source.title,
            style: 'h3',
            width: 280
          }]
        });
        this.addContent({
          columns: [{
            image: pair[0].element,
            width: 270
          }, {
            image: pair[1].element,
            width: 270
          }]
        });
        this.addNewLine();
        pair = [];
      }
    }

    if (double_vis.length % 2 !== 0) {
      const item = double_vis[double_vis.length - 1];
      const title = this.checkTitle(item, isAgents, tab);
      this.addContent({
        columns: [{
          id: 'splitsinglevis' + title[0]._source.title,
          text: title[0]._source.title,
          style: 'h3',
          width: 280
        }]
      });
      this.addContent({
        columns: [{
          image: item.element,
          width: 280
        }]
      });
      this.addNewLine();
    }
  }

  formatDate(date) {
    (0, _logger.log)('reporting:formatDate', `Format date ${date}`, 'info');
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    const hours = date.getHours();
    const minutes = date.getMinutes();
    const seconds = date.getSeconds();
    const str = `${year}-${month < 10 ? '0' + month : month}-${day < 10 ? '0' + day : day}T${hours < 10 ? '0' + hours : hours}:${minutes < 10 ? '0' + minutes : minutes}:${seconds < 10 ? '0' + seconds : seconds}`;
    (0, _logger.log)('reporting:formatDate', `str: ${str}`, 'debug');
    return str;
  }

  checkTitle(item, isAgents, tab) {
    (0, _logger.log)('reporting:checkTitle', `Item ID ${item.id}, from ${isAgents ? 'agents' : 'overview'} and tab ${tab}`, 'info');
    const title = isAgents ? _visualizations.AgentsVisualizations[tab].filter(v => v._id === item.id) : _visualizations.OverviewVisualizations[tab].filter(v => v._id === item.id);
    return title;
  }

  addSimpleTable({
    columns,
    items,
    title
  }) {
    if (title) {
      this.addContent(typeof title === 'string' ? {
        text: title,
        style: 'h4'
      } : title).addNewLine();
    }

    if (!items || !items.length) {
      this.addContent({
        text: 'No results match your search criteria',
        style: 'standard'
      });
      return this;
    }

    const tableHeader = columns.map(column => {
      return {
        text: column.label,
        style: 'whiteColor',
        border: [0, 0, 0, 0]
      };
    });
    const tableRows = items.map((item, index) => {
      return columns.map(column => {
        const cellValue = item[column.id];
        return {
          text: typeof cellValue !== 'undefined' ? cellValue : '-',
          style: 'standard'
        };
      });
    });
    const widths = new Array(columns.length - 1).fill('auto');
    widths.push('*');
    this.addContent({
      fontSize: 8,
      table: {
        headerRows: 1,
        widths,
        body: [tableHeader, ...tableRows]
      },
      layout: {
        fillColor: i => i === 0 ? COLORS.PRIMARY : null,
        hLineColor: () => COLORS.PRIMARY,
        hLineWidth: () => 1,
        vLineWidth: () => 0
      }
    }).addNewLine();
    return this;
  }

  addList({
    title,
    list
  }) {
    return this.addContentWithNewLine(typeof title === 'string' ? {
      text: title,
      style: 'h2'
    } : title).addContent({
      ul: list.filter(element => element)
    }).addNewLine();
  }

  addNewLine() {
    return this.addContent({
      text: '\n'
    });
  }

  addContentWithNewLine(title) {
    return this.addContent(title).addNewLine();
  }

  addAgentsFilters(agents) {
    (0, _logger.log)('reporting:addAgentsFilters', `Started to render the authorized agents filters`, 'info');
    (0, _logger.log)('reporting:addAgentsFilters', `agents: ${agents}`, 'debug');
    this.addNewLine();
    this.addContent({
      text: 'NOTE: This report only includes the authorized agents of the user who generated the report',
      style: {
        fontSize: 10,
        color: COLORS.PRIMARY
      },
      margin: [0, 0, 0, 5]
    });
    /*TODO: This will be enabled by a config*/

    /* this.addContent({
      fontSize: 8,
      table: {
        widths: ['*'],
        body: [
          [
            {
              columns: [
                {
                  svg: filterIconRaw,
                  width: 10,
                  height: 10,
                  margin: [40, 6, 0, 0]
                },
                {
                  text: `Agent IDs: ${agents}` || '-',
                  margin: [43, 0, 0, 0],
                  style: { fontSize: 8, color: '#333' }
                }
              ]
            }
          ]
        ]
      },
      margin: [-40, 0, -40, 0],
      layout: {
        fillColor: () => null,
        hLineWidth: () => 0,
        vLineWidth: () => 0
      }
    }); */

    this.addContent({
      text: '\n'
    });
    (0, _logger.log)('reporting:addAgentsFilters', 'Time range and filters rendered', 'debug');
  }

  async print(path) {
    const document = this._printer.createPdfKitDocument({ ...pageConfiguration,
      content: this._content
    });

    await document.pipe(_fs.default.createWriteStream(path));
    document.end();
  }

}

exports.ReportPrinter = ReportPrinter;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInByaW50ZXIudHMiXSwibmFtZXMiOlsiQ09MT1JTIiwiUFJJTUFSWSIsInBhZ2VDb25maWd1cmF0aW9uIiwic3R5bGVzIiwiaDEiLCJmb250U2l6ZSIsIm1vbnNsaWdodCIsImNvbG9yIiwiaDIiLCJoMyIsImg0Iiwic3RhbmRhcmQiLCJ3aGl0ZUNvbG9yRmlsdGVycyIsIndoaXRlQ29sb3IiLCJwYWdlTWFyZ2lucyIsImhlYWRlciIsIm1hcmdpbiIsImNvbHVtbnMiLCJpbWFnZSIsInBhdGgiLCJqb2luIiwiX19kaXJuYW1lIiwid2lkdGgiLCJ0ZXh0IiwiYWxpZ25tZW50IiwiY29udGVudCIsImZvb3RlciIsImN1cnJlbnRQYWdlIiwicGFnZUNvdW50IiwidG9TdHJpbmciLCJwYWdlQnJlYWtCZWZvcmUiLCJjdXJyZW50Tm9kZSIsImZvbGxvd2luZ05vZGVzT25QYWdlIiwiaWQiLCJpbmNsdWRlcyIsImxlbmd0aCIsImZvbnRzIiwiUm9ib3RvIiwibm9ybWFsIiwiYm9sZCIsIml0YWxpY3MiLCJib2xkaXRhbGljcyIsIlJlcG9ydFByaW50ZXIiLCJjb25zdHJ1Y3RvciIsIl9wcmludGVyIiwiUGRmUHJpbnRlciIsIl9jb250ZW50IiwiYWRkQ29udGVudCIsInB1c2giLCJhZGRDb25maWdUYWJsZXMiLCJ0YWJsZXMiLCJ0YWJsZSIsInJvd3NwYXJzZWQiLCJyb3dzIiwiQXJyYXkiLCJpc0FycmF5Iiwic2xpY2UiLCJ0aXRsZSIsInN0eWxlIiwidHlwZSIsImZ1bGxfYm9keSIsIm1vZGlmaWVkUm93cyIsIm1hcCIsInJvdyIsImNlbGwiLCJ3aWR0aHMiLCJmaWxsIiwiY29sIiwiYm9yZGVyIiwiY29sU3BhbiIsImhlYWRlclJvd3MiLCJib2R5IiwiZG9udEJyZWFrUm93cyIsImxheW91dCIsImZpbGxDb2xvciIsImkiLCJoTGluZUNvbG9yIiwiaExpbmVXaWR0aCIsInZMaW5lV2lkdGgiLCJhZGROZXdMaW5lIiwiYWRkVGFibGVzIiwicGFnZUJyZWFrIiwic29ydFRhYmxlUm93cyIsImEiLCJiIiwicGFyc2VJbnQiLCJUaW1Tb3J0Iiwic29ydCIsImFkZFRpbWVSYW5nZUFuZEZpbHRlcnMiLCJmcm9tIiwidG8iLCJmaWx0ZXJzIiwidGltZVpvbmUiLCJmcm9tRGF0ZSIsIkRhdGUiLCJ0b0xvY2FsZVN0cmluZyIsInRvRGF0ZSIsInN0ciIsImZvcm1hdERhdGUiLCJzdmciLCJjbG9ja0ljb25SYXciLCJoZWlnaHQiLCJmaWx0ZXJJY29uUmF3IiwiYWRkVmlzdWFsaXphdGlvbnMiLCJ2aXN1YWxpemF0aW9ucyIsImlzQWdlbnRzIiwidGFiIiwic2luZ2xlX3ZpcyIsImZpbHRlciIsIml0ZW0iLCJkb3VibGVfdmlzIiwiZm9yRWFjaCIsInZpc3VhbGl6YXRpb24iLCJjaGVja1RpdGxlIiwiX3NvdXJjZSIsImVsZW1lbnQiLCJwYWlyIiwidGl0bGVfMSIsInRpdGxlXzIiLCJkYXRlIiwieWVhciIsImdldEZ1bGxZZWFyIiwibW9udGgiLCJnZXRNb250aCIsImRheSIsImdldERhdGUiLCJob3VycyIsImdldEhvdXJzIiwibWludXRlcyIsImdldE1pbnV0ZXMiLCJzZWNvbmRzIiwiZ2V0U2Vjb25kcyIsIkFnZW50c1Zpc3VhbGl6YXRpb25zIiwidiIsIl9pZCIsIk92ZXJ2aWV3VmlzdWFsaXphdGlvbnMiLCJhZGRTaW1wbGVUYWJsZSIsIml0ZW1zIiwidGFibGVIZWFkZXIiLCJjb2x1bW4iLCJsYWJlbCIsInRhYmxlUm93cyIsImluZGV4IiwiY2VsbFZhbHVlIiwiYWRkTGlzdCIsImxpc3QiLCJhZGRDb250ZW50V2l0aE5ld0xpbmUiLCJ1bCIsImFkZEFnZW50c0ZpbHRlcnMiLCJhZ2VudHMiLCJwcmludCIsImRvY3VtZW50IiwiY3JlYXRlUGRmS2l0RG9jdW1lbnQiLCJwaXBlIiwiZnMiLCJjcmVhdGVXcml0ZVN0cmVhbSIsImVuZCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUlBOztBQUNBOzs7Ozs7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QUFRO0FBQ3RCLHFCQUNFLDRCQURGLEVBRUcsaURBRkgsRUFHRSxNQUhGO0FBS0EscUJBQ0UsNEJBREYsRUFFRyxXQUFVQSxNQUFPLEVBRnBCLEVBR0UsT0FIRjtBQU1BLFNBQUt0RSxVQUFMO0FBRUEsU0FBS2hDLFVBQUwsQ0FBZ0I7QUFDZHhCLE1BQUFBLElBQUksRUFDRiw0RkFGWTtBQUdkbUMsTUFBQUEsS0FBSyxFQUFFO0FBQUVyRCxRQUFBQSxRQUFRLEVBQUUsRUFBWjtBQUFnQkUsUUFBQUEsS0FBSyxFQUFFUCxNQUFNLENBQUNDO0FBQTlCLE9BSE87QUFJZGUsTUFBQUEsTUFBTSxFQUFFLENBQUMsQ0FBRCxFQUFJLENBQUosRUFBTyxDQUFQLEVBQVUsQ0FBVjtBQUpNLEtBQWhCO0FBT0E7O0FBQ0E7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBZ0NBLFNBQUsrQixVQUFMLENBQWdCO0FBQUV4QixNQUFBQSxJQUFJLEVBQUU7QUFBUixLQUFoQjtBQUNBLHFCQUNFLDRCQURGLEVBRUUsaUNBRkYsRUFHRSxPQUhGO0FBS0Q7O0FBRUQsUUFBTStILEtBQU4sQ0FBWW5JLElBQVosRUFBeUI7QUFDdkIsVUFBTW9JLFFBQVEsR0FBRyxLQUFLM0csUUFBTCxDQUFjNEcsb0JBQWQsQ0FBbUMsRUFBQyxHQUFHdEosaUJBQUo7QUFBdUJ1QixNQUFBQSxPQUFPLEVBQUUsS0FBS3FCO0FBQXJDLEtBQW5DLENBQWpCOztBQUNBLFVBQU15RyxRQUFRLENBQUNFLElBQVQsQ0FDSkMsWUFBR0MsaUJBQUgsQ0FBcUJ4SSxJQUFyQixDQURJLENBQU47QUFHQW9JLElBQUFBLFFBQVEsQ0FBQ0ssR0FBVDtBQUNEOztBQXhkdUIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHBhdGggZnJvbSAncGF0aCc7XG5pbXBvcnQgUGRmUHJpbnRlciBmcm9tICdwZGZtYWtlL3NyYy9wcmludGVyJztcbmltcG9ydCBjbG9ja0ljb25SYXcgZnJvbSAnLi9jbG9jay1pY29uLXJhdyc7XG5pbXBvcnQgZmlsdGVySWNvblJhdyBmcm9tICcuL2ZpbHRlci1pY29uLXJhdyc7XG5pbXBvcnQge1xuICBBZ2VudHNWaXN1YWxpemF0aW9ucyxcbiAgT3ZlcnZpZXdWaXN1YWxpemF0aW9uc1xufSBmcm9tICcuLi8uLi9pbnRlZ3JhdGlvbi1maWxlcy92aXN1YWxpemF0aW9ucyc7XG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuLi9sb2dnZXInO1xuaW1wb3J0ICogYXMgVGltU29ydCBmcm9tICd0aW1zb3J0JztcblxuY29uc3QgQ09MT1JTID0ge1xuICBQUklNQVJZOiAnIzAwYTllNSdcbn07XG5cbmNvbnN0IHBhZ2VDb25maWd1cmF0aW9uID0ge1xuICBzdHlsZXM6IHtcbiAgICBoMToge1xuICAgICAgZm9udFNpemU6IDIyLFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBoMjoge1xuICAgICAgZm9udFNpemU6IDE4LFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBoMzoge1xuICAgICAgZm9udFNpemU6IDE2LFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBoNDoge1xuICAgICAgZm9udFNpemU6IDE0LFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBzdGFuZGFyZDoge1xuICAgICAgY29sb3I6ICcjMzMzJ1xuICAgIH0sXG4gICAgd2hpdGVDb2xvckZpbHRlcnM6IHtcbiAgICAgIGNvbG9yOiAnI0ZGRicsXG4gICAgICBmb250U2l6ZTogMTRcbiAgICB9LFxuICAgIHdoaXRlQ29sb3I6IHtcbiAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICB9XG4gIH0sXG4gIHBhZ2VNYXJnaW5zOiBbNDAsIDgwLCA0MCwgODBdLFxuICBoZWFkZXI6IHtcbiAgICBtYXJnaW46IFs0MCwgMjAsIDAsIDBdLFxuICAgIGNvbHVtbnM6IFtcbiAgICAgIHtcbiAgICAgICAgaW1hZ2U6IHBhdGguam9pbihfX2Rpcm5hbWUsICcuLi8uLi8uLi9wdWJsaWMvYXNzZXRzL2xvZ28ucG5nJyksXG4gICAgICAgIHdpZHRoOiAxOTBcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIHRleHQ6ICdpbmZvQHdhenVoLmNvbVxcbmh0dHBzOi8vd2F6dWguY29tJyxcbiAgICAgICAgYWxpZ25tZW50OiAncmlnaHQnLFxuICAgICAgICBtYXJnaW46IFswLCAwLCA0MCwgMF0sXG4gICAgICAgIGNvbG9yOiBDT0xPUlMuUFJJTUFSWVxuICAgICAgfVxuICAgIF1cbiAgfSxcbiAgY29udGVudDogW10sXG4gIGZvb3RlcihjdXJyZW50UGFnZSwgcGFnZUNvdW50KSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6ICdDb3B5cmlnaHQgwqkgMjAyMSBXYXp1aCwgSW5jLicsXG4gICAgICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZLFxuICAgICAgICAgIG1hcmdpbjogWzQwLCA0MCwgMCwgMF1cbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6ICdQYWdlICcgKyBjdXJyZW50UGFnZS50b1N0cmluZygpICsgJyBvZiAnICsgcGFnZUNvdW50LFxuICAgICAgICAgIGFsaWdubWVudDogJ3JpZ2h0JyxcbiAgICAgICAgICBtYXJnaW46IFswLCA0MCwgNDAsIDBdLFxuICAgICAgICAgIGNvbG9yOiBDT0xPUlMuUFJJTUFSWVxuICAgICAgICB9XG4gICAgICBdXG4gICAgfTtcbiAgfSxcbiAgcGFnZUJyZWFrQmVmb3JlKGN1cnJlbnROb2RlLCBmb2xsb3dpbmdOb2Rlc09uUGFnZSkge1xuICAgIGlmIChjdXJyZW50Tm9kZS5pZCAmJiBjdXJyZW50Tm9kZS5pZC5pbmNsdWRlcygnc3BsaXR2aXMnKSkge1xuICAgICAgcmV0dXJuIChcbiAgICAgICAgZm9sbG93aW5nTm9kZXNPblBhZ2UubGVuZ3RoID09PSA2IHx8XG4gICAgICAgIGZvbGxvd2luZ05vZGVzT25QYWdlLmxlbmd0aCA9PT0gN1xuICAgICAgKTtcbiAgICB9XG4gICAgaWYgKFxuICAgICAgKGN1cnJlbnROb2RlLmlkICYmIGN1cnJlbnROb2RlLmlkLmluY2x1ZGVzKCdzcGxpdHNpbmdsZXZpcycpKSB8fFxuICAgICAgKGN1cnJlbnROb2RlLmlkICYmIGN1cnJlbnROb2RlLmlkLmluY2x1ZGVzKCdzaW5nbGV2aXMnKSlcbiAgICApIHtcbiAgICAgIHJldHVybiBmb2xsb3dpbmdOb2Rlc09uUGFnZS5sZW5ndGggPT09IDY7XG4gICAgfVxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufTtcblxuY29uc3QgZm9udHMgPSB7XG4gIFJvYm90bzoge1xuICAgIG5vcm1hbDogcGF0aC5qb2luKFxuICAgICAgX19kaXJuYW1lLFxuICAgICAgJy4uLy4uLy4uL3B1YmxpYy9hc3NldHMvb3BlbnNhbnMvT3BlblNhbnMtTGlnaHQudHRmJ1xuICAgICksXG4gICAgYm9sZDogcGF0aC5qb2luKFxuICAgICAgX19kaXJuYW1lLFxuICAgICAgJy4uLy4uLy4uL3B1YmxpYy9hc3NldHMvb3BlbnNhbnMvT3BlblNhbnMtQm9sZC50dGYnXG4gICAgKSxcbiAgICBpdGFsaWNzOiBwYXRoLmpvaW4oXG4gICAgICBfX2Rpcm5hbWUsXG4gICAgICAnLi4vLi4vLi4vcHVibGljL2Fzc2V0cy9vcGVuc2Fucy9PcGVuU2Fucy1JdGFsaWMudHRmJ1xuICAgICksXG4gICAgYm9sZGl0YWxpY3M6IHBhdGguam9pbihcbiAgICAgIF9fZGlybmFtZSxcbiAgICAgICcuLi8uLi8uLi9wdWJsaWMvYXNzZXRzL29wZW5zYW5zL09wZW5TYW5zLUJvbGRJdGFsaWMudHRmJ1xuICAgICksXG4gICAgbW9uc2xpZ2h0OiBwYXRoLmpvaW4oXG4gICAgICBfX2Rpcm5hbWUsXG4gICAgICAnLi4vLi4vLi4vcHVibGljL2Fzc2V0cy9vcGVuc2Fucy9Nb250c2VycmF0LUxpZ2h0LnR0ZidcbiAgICApXG4gIH1cbn07XG5cbmV4cG9ydCBjbGFzcyBSZXBvcnRQcmludGVye1xuICBwcml2YXRlIF9jb250ZW50OiBhbnlbXTtcbiAgcHJpdmF0ZSBfcHJpbnRlcjogUGRmUHJpbnRlcjtcbiAgY29uc3RydWN0b3IoKXtcbiAgICB0aGlzLl9wcmludGVyID0gbmV3IFBkZlByaW50ZXIoZm9udHMpO1xuICAgIHRoaXMuX2NvbnRlbnQgPSBbXTtcbiAgfVxuICBhZGRDb250ZW50KC4uLmNvbnRlbnQ6IGFueSl7XG4gICAgdGhpcy5fY29udGVudC5wdXNoKC4uLmNvbnRlbnQpO1xuICAgIHJldHVybiB0aGlzO1xuICB9XG4gIGFkZENvbmZpZ1RhYmxlcyh0YWJsZXM6IGFueSl7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzpyZW5kZXJDb25maWdUYWJsZXMnLFxuICAgICAgJ1N0YXJ0ZWQgdG8gcmVuZGVyIGNvbmZpZ3VyYXRpb24gdGFibGVzJyxcbiAgICAgICdpbmZvJ1xuICAgICk7XG4gICAgbG9nKCdyZXBvcnRpbmc6cmVuZGVyQ29uZmlnVGFibGVzJywgYHRhYmxlczogJHt0YWJsZXMubGVuZ3RofWAsICdkZWJ1ZycpO1xuICAgIGZvciAoY29uc3QgdGFibGUgb2YgdGFibGVzKSB7XG4gICAgICBsZXQgcm93c3BhcnNlZCA9IHRhYmxlLnJvd3M7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShyb3dzcGFyc2VkKSAmJiByb3dzcGFyc2VkLmxlbmd0aCkge1xuICAgICAgICBjb25zdCByb3dzID1cbiAgICAgICAgICByb3dzcGFyc2VkLmxlbmd0aCA+IDEwMCA/IHJvd3NwYXJzZWQuc2xpY2UoMCwgOTkpIDogcm93c3BhcnNlZDtcbiAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICB0ZXh0OiB0YWJsZS50aXRsZSxcbiAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMTEsIGNvbG9yOiAnIzAwMCcgfSxcbiAgICAgICAgICBtYXJnaW46IHRhYmxlLnRpdGxlICYmIHRhYmxlLnR5cGUgPT09ICd0YWJsZScgPyBbMCwgMCwgMCwgNV0gOiAnJ1xuICAgICAgICB9KTtcblxuICAgICAgICBpZiAodGFibGUudGl0bGUgPT09ICdNb25pdG9yZWQgZGlyZWN0b3JpZXMnKSB7XG4gICAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6XG4gICAgICAgICAgICAgICdSVDogUmVhbCB0aW1lIHwgV0Q6IFdoby1kYXRhIHwgUGVyLjogUGVybWlzc2lvbiB8IE1UOiBNb2RpZmljYXRpb24gdGltZSB8IFNMOiBTeW1ib2xpYyBsaW5rIHwgUkw6IFJlY3Vyc2lvbiBsZXZlbCcsXG4gICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogOCwgY29sb3I6IENPTE9SUy5QUklNQVJZIH0sXG4gICAgICAgICAgICBtYXJnaW46IFswLCAwLCAwLCA1XVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZnVsbF9ib2R5ID0gW107XG5cbiAgICAgICAgY29uc3QgbW9kaWZpZWRSb3dzID0gcm93cy5tYXAocm93ID0+IHJvdy5tYXAoY2VsbCA9PiAoeyB0ZXh0OiBjZWxsIHx8ICctJywgc3R5bGU6ICdzdGFuZGFyZCcgfSkpKTtcbiAgICAgICAgLy8gZm9yIChjb25zdCByb3cgb2Ygcm93cykge1xuICAgICAgICAvLyAgIG1vZGlmaWVkUm93cy5wdXNoKFxuICAgICAgICAvLyAgICAgcm93Lm1hcChjZWxsID0+ICh7IHRleHQ6IGNlbGwgfHwgJy0nLCBzdHlsZTogJ3N0YW5kYXJkJyB9KSlcbiAgICAgICAgLy8gICApO1xuICAgICAgICAvLyB9XG4gICAgICAgIGxldCB3aWR0aHMgPSBbXTtcbiAgICAgICAgd2lkdGhzID0gQXJyYXkodGFibGUuY29sdW1ucy5sZW5ndGggLSAxKS5maWxsKCdhdXRvJyk7XG4gICAgICAgIHdpZHRocy5wdXNoKCcqJyk7XG5cbiAgICAgICAgaWYgKHRhYmxlLnR5cGUgPT09ICdjb25maWcnKSB7XG4gICAgICAgICAgZnVsbF9ib2R5LnB1c2goXG4gICAgICAgICAgICB0YWJsZS5jb2x1bW5zLm1hcChjb2wgPT4gKHtcbiAgICAgICAgICAgICAgdGV4dDogY29sIHx8ICctJyxcbiAgICAgICAgICAgICAgYm9yZGVyOiBbMCwgMCwgMCwgMjBdLFxuICAgICAgICAgICAgICBmb250U2l6ZTogMCxcbiAgICAgICAgICAgICAgY29sU3BhbjogMlxuICAgICAgICAgICAgfSkpLFxuICAgICAgICAgICAgLi4ubW9kaWZpZWRSb3dzXG4gICAgICAgICAgKTtcbiAgICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgZm9udFNpemU6IDgsXG4gICAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgICBoZWFkZXJSb3dzOiAwLFxuICAgICAgICAgICAgICB3aWR0aHMsXG4gICAgICAgICAgICAgIGJvZHk6IGZ1bGxfYm9keSxcbiAgICAgICAgICAgICAgZG9udEJyZWFrUm93czogdHJ1ZVxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGxheW91dDoge1xuICAgICAgICAgICAgICBmaWxsQ29sb3I6IGkgPT4gKGkgPT09IDAgPyAnI2ZmZicgOiBudWxsKSxcbiAgICAgICAgICAgICAgaExpbmVDb2xvcjogKCkgPT4gJyNEM0RBRTYnLFxuICAgICAgICAgICAgICBoTGluZVdpZHRoOiAoKSA9PiAxLFxuICAgICAgICAgICAgICB2TGluZVdpZHRoOiAoKSA9PiAwXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSBpZiAodGFibGUudHlwZSA9PT0gJ3RhYmxlJykge1xuICAgICAgICAgIGZ1bGxfYm9keS5wdXNoKFxuICAgICAgICAgICAgdGFibGUuY29sdW1ucy5tYXAoY29sID0+ICh7XG4gICAgICAgICAgICAgIHRleHQ6IGNvbCB8fCAnLScsXG4gICAgICAgICAgICAgIHN0eWxlOiAnd2hpdGVDb2xvcicsXG4gICAgICAgICAgICAgIGJvcmRlcjogWzAsIDAsIDAsIDBdXG4gICAgICAgICAgICB9KSksXG4gICAgICAgICAgICAuLi5tb2RpZmllZFJvd3NcbiAgICAgICAgICApO1xuICAgICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgICBmb250U2l6ZTogOCxcbiAgICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICAgIGhlYWRlclJvd3M6IDEsXG4gICAgICAgICAgICAgIHdpZHRocyxcbiAgICAgICAgICAgICAgYm9keTogZnVsbF9ib2R5XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgbGF5b3V0OiB7XG4gICAgICAgICAgICAgIGZpbGxDb2xvcjogaSA9PiAoaSA9PT0gMCA/IENPTE9SUy5QUklNQVJZIDogbnVsbCksXG4gICAgICAgICAgICAgIGhMaW5lQ29sb3I6ICgpID0+IENPTE9SUy5QUklNQVJZLFxuICAgICAgICAgICAgICBoTGluZVdpZHRoOiAoKSA9PiAxLFxuICAgICAgICAgICAgICB2TGluZVdpZHRoOiAoKSA9PiAwXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgICB9XG4gICAgICBsb2coJ3JlcG9ydGluZzpyZW5kZXJDb25maWdUYWJsZXMnLCBgVGFibGUgcmVuZGVyZWRgLCAnZGVidWcnKTtcbiAgICB9XG4gIH1cblxuICBhZGRUYWJsZXModGFibGVzOiBhbnkpe1xuICAgIGxvZygncmVwb3J0aW5nOnJlbmRlclRhYmxlcycsICdTdGFydGVkIHRvIHJlbmRlciB0YWJsZXMnLCAnaW5mbycpO1xuICAgIGxvZygncmVwb3J0aW5nOnJlbmRlclRhYmxlcycsIGB0YWJsZXM6ICR7dGFibGVzLmxlbmd0aH1gLCAnZGVidWcnKTtcbiAgICBmb3IgKGNvbnN0IHRhYmxlIG9mIHRhYmxlcykge1xuICAgICAgbGV0IHJvd3NwYXJzZWQgPSBbXTtcbiAgICAgIHJvd3NwYXJzZWQgPSB0YWJsZS5yb3dzO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkocm93c3BhcnNlZCkgJiYgcm93c3BhcnNlZC5sZW5ndGgpIHtcbiAgICAgICAgY29uc3Qgcm93cyA9XG4gICAgICAgICAgcm93c3BhcnNlZC5sZW5ndGggPiAxMDAgPyByb3dzcGFyc2VkLnNsaWNlKDAsIDk5KSA6IHJvd3NwYXJzZWQ7XG4gICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgdGV4dDogdGFibGUudGl0bGUsXG4gICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgcGFnZUJyZWFrOiAnYmVmb3JlJ1xuICAgICAgICB9KTtcbiAgICAgICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgICAgIGNvbnN0IGZ1bGxfYm9keSA9IFtdO1xuICAgICAgICBjb25zdCBzb3J0VGFibGVSb3dzID0gKGEsIGIpID0+XG4gICAgICAgICAgcGFyc2VJbnQoYVthLmxlbmd0aCAtIDFdKSA8IHBhcnNlSW50KGJbYi5sZW5ndGggLSAxXSlcbiAgICAgICAgICAgID8gMVxuICAgICAgICAgICAgOiBwYXJzZUludChhW2EubGVuZ3RoIC0gMV0pID4gcGFyc2VJbnQoYltiLmxlbmd0aCAtIDFdKVxuICAgICAgICAgICAgPyAtMVxuICAgICAgICAgICAgOiAwO1xuXG4gICAgICAgIFRpbVNvcnQuc29ydChyb3dzLCBzb3J0VGFibGVSb3dzKTtcblxuICAgICAgICBjb25zdCBtb2RpZmllZFJvd3MgPSByb3dzLm1hcChyb3cgPT4gcm93Lm1hcChjZWxsID0+ICh7IHRleHQ6IGNlbGwgfHwgJy0nLCBzdHlsZTogJ3N0YW5kYXJkJyB9KSkpO1xuXG4gICAgICAgIGNvbnN0IHdpZHRocyA9IEFycmF5KHRhYmxlLmNvbHVtbnMubGVuZ3RoIC0gMSkuZmlsbCgnYXV0bycpO1xuICAgICAgICB3aWR0aHMucHVzaCgnKicpO1xuXG4gICAgICAgIGZ1bGxfYm9keS5wdXNoKFxuICAgICAgICAgIHRhYmxlLmNvbHVtbnMubWFwKGNvbCA9PiAoe1xuICAgICAgICAgICAgdGV4dDogY29sIHx8ICctJyxcbiAgICAgICAgICAgIHN0eWxlOiAnd2hpdGVDb2xvcicsXG4gICAgICAgICAgICBib3JkZXI6IFswLCAwLCAwLCAwXVxuICAgICAgICAgIH0pKSxcbiAgICAgICAgICAuLi5tb2RpZmllZFJvd3NcbiAgICAgICAgKTtcbiAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICBmb250U2l6ZTogOCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgaGVhZGVyUm93czogMSxcbiAgICAgICAgICAgIHdpZHRocyxcbiAgICAgICAgICAgIGJvZHk6IGZ1bGxfYm9keVxuICAgICAgICAgIH0sXG4gICAgICAgICAgbGF5b3V0OiB7XG4gICAgICAgICAgICBmaWxsQ29sb3I6IGkgPT4gKGkgPT09IDAgPyBDT0xPUlMuUFJJTUFSWSA6IG51bGwpLFxuICAgICAgICAgICAgaExpbmVDb2xvcjogKCkgPT4gQ09MT1JTLlBSSU1BUlksXG4gICAgICAgICAgICBoTGluZVdpZHRoOiAoKSA9PiAxLFxuICAgICAgICAgICAgdkxpbmVXaWR0aDogKCkgPT4gMFxuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIHRoaXMuYWRkTmV3TGluZSgpO1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpyZW5kZXJUYWJsZXMnLCBgVGFibGUgcmVuZGVyZWRgLCAnZGVidWcnKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgYWRkVGltZVJhbmdlQW5kRmlsdGVycyhmcm9tLCB0bywgZmlsdGVycywgdGltZVpvbmUpe1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6cmVuZGVyVGltZVJhbmdlQW5kRmlsdGVycycsXG4gICAgICBgU3RhcnRlZCB0byByZW5kZXIgdGhlIHRpbWUgcmFuZ2UgYW5kIHRoZSBmaWx0ZXJzYCxcbiAgICAgICdpbmZvJ1xuICAgICk7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzpyZW5kZXJUaW1lUmFuZ2VBbmRGaWx0ZXJzJyxcbiAgICAgIGBmcm9tOiAke2Zyb219LCB0bzogJHt0b30sIGZpbHRlcnM6ICR7ZmlsdGVyc30sIHRpbWVab25lOiAke3RpbWVab25lfWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgICBjb25zdCBmcm9tRGF0ZSA9IG5ldyBEYXRlKFxuICAgICAgbmV3IERhdGUoZnJvbSkudG9Mb2NhbGVTdHJpbmcoJ2VuLVVTJywgeyB0aW1lWm9uZSB9KVxuICAgICk7XG4gICAgY29uc3QgdG9EYXRlID0gbmV3IERhdGUobmV3IERhdGUodG8pLnRvTG9jYWxlU3RyaW5nKCdlbi1VUycsIHsgdGltZVpvbmUgfSkpO1xuICAgIGNvbnN0IHN0ciA9IGAke3RoaXMuZm9ybWF0RGF0ZShmcm9tRGF0ZSl9IHRvICR7dGhpcy5mb3JtYXREYXRlKHRvRGF0ZSl9YDtcblxuICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICBmb250U2l6ZTogOCxcbiAgICAgIHRhYmxlOiB7XG4gICAgICAgIHdpZHRoczogWycqJ10sXG4gICAgICAgIGJvZHk6IFtcbiAgICAgICAgICBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICBzdmc6IGNsb2NrSWNvblJhdyxcbiAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMCxcbiAgICAgICAgICAgICAgICAgIGhlaWdodDogMTAsXG4gICAgICAgICAgICAgICAgICBtYXJnaW46IFs0MCwgNSwgMCwgMF1cbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgIHRleHQ6IHN0ciB8fCAnLScsXG4gICAgICAgICAgICAgICAgICBtYXJnaW46IFs0MywgMCwgMCwgMF0sXG4gICAgICAgICAgICAgICAgICBzdHlsZTogJ3doaXRlQ29sb3JGaWx0ZXJzJ1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgfVxuICAgICAgICAgIF0sXG4gICAgICAgICAgW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgc3ZnOiBmaWx0ZXJJY29uUmF3LFxuICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwLFxuICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMCxcbiAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzQwLCA2LCAwLCAwXVxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgdGV4dDogZmlsdGVycyB8fCAnLScsXG4gICAgICAgICAgICAgICAgICBtYXJnaW46IFs0MywgMCwgMCwgMF0sXG4gICAgICAgICAgICAgICAgICBzdHlsZTogJ3doaXRlQ29sb3JGaWx0ZXJzJ1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgXVxuICAgICAgfSxcbiAgICAgIG1hcmdpbjogWy00MCwgMCwgLTQwLCAwXSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBmaWxsQ29sb3I6ICgpID0+IENPTE9SUy5QUklNQVJZLFxuICAgICAgICBoTGluZVdpZHRoOiAoKSA9PiAwLFxuICAgICAgICB2TGluZVdpZHRoOiAoKSA9PiAwXG4gICAgICB9XG4gICAgfSk7XG5cbiAgICB0aGlzLmFkZENvbnRlbnQoeyB0ZXh0OiAnXFxuJyB9KTtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnJlbmRlclRpbWVSYW5nZUFuZEZpbHRlcnMnLFxuICAgICAgJ1RpbWUgcmFuZ2UgYW5kIGZpbHRlcnMgcmVuZGVyZWQnLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gIH1cbiAgYWRkVmlzdWFsaXphdGlvbnModmlzdWFsaXphdGlvbnMsIGlzQWdlbnRzLCB0YWIpe1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6cmVuZGVyVmlzdWFsaXphdGlvbnMnLFxuICAgICAgYCR7dmlzdWFsaXphdGlvbnMubGVuZ3RofSB2aXN1YWxpemF0aW9ucyBmb3IgdGFiICR7dGFifWAsXG4gICAgICAnaW5mbydcbiAgICApO1xuICAgIGNvbnN0IHNpbmdsZV92aXMgPSB2aXN1YWxpemF0aW9ucy5maWx0ZXIoaXRlbSA9PiBpdGVtLndpZHRoID49IDYwMCk7XG4gICAgY29uc3QgZG91YmxlX3ZpcyA9IHZpc3VhbGl6YXRpb25zLmZpbHRlcihpdGVtID0+IGl0ZW0ud2lkdGggPCA2MDApO1xuXG4gICAgc2luZ2xlX3Zpcy5mb3JFYWNoKHZpc3VhbGl6YXRpb24gPT4ge1xuICAgICAgY29uc3QgdGl0bGUgPSB0aGlzLmNoZWNrVGl0bGUodmlzdWFsaXphdGlvbiwgaXNBZ2VudHMsIHRhYik7XG4gICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICBpZDogJ3NpbmdsZXZpcycgKyB0aXRsZVswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICB0ZXh0OiB0aXRsZVswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICBzdHlsZTogJ2gzJ1xuICAgICAgfSk7XG4gICAgICB0aGlzLmFkZENvbnRlbnQoeyBjb2x1bW5zOiBbeyBpbWFnZTogdmlzdWFsaXphdGlvbi5lbGVtZW50LCB3aWR0aDogNTAwIH1dIH0pO1xuICAgICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgfSlcblxuICAgIGxldCBwYWlyID0gW107XG5cbiAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgZG91YmxlX3Zpcykge1xuICAgICAgcGFpci5wdXNoKGl0ZW0pO1xuICAgICAgaWYgKHBhaXIubGVuZ3RoID09PSAyKSB7XG4gICAgICAgIGNvbnN0IHRpdGxlXzEgPSB0aGlzLmNoZWNrVGl0bGUocGFpclswXSwgaXNBZ2VudHMsIHRhYik7XG4gICAgICAgIGNvbnN0IHRpdGxlXzIgPSB0aGlzLmNoZWNrVGl0bGUocGFpclsxXSwgaXNBZ2VudHMsIHRhYik7XG5cbiAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnc3BsaXR2aXMnICsgdGl0bGVfMVswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICAgICAgICB0ZXh0OiB0aXRsZV8xWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICAgICAgICB3aWR0aDogMjgwXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ3NwbGl0dmlzJyArIHRpdGxlXzJbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgICAgICAgdGV4dDogdGl0bGVfMlswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgICAgICAgd2lkdGg6IDI4MFxuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICB7IGltYWdlOiBwYWlyWzBdLmVsZW1lbnQsIHdpZHRoOiAyNzAgfSxcbiAgICAgICAgICAgIHsgaW1hZ2U6IHBhaXJbMV0uZWxlbWVudCwgd2lkdGg6IDI3MCB9XG4gICAgICAgICAgXVxuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmFkZE5ld0xpbmUoKTtcbiAgICAgICAgcGFpciA9IFtdO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChkb3VibGVfdmlzLmxlbmd0aCAlIDIgIT09IDApIHtcbiAgICAgIGNvbnN0IGl0ZW0gPSBkb3VibGVfdmlzW2RvdWJsZV92aXMubGVuZ3RoIC0gMV07XG4gICAgICBjb25zdCB0aXRsZSA9IHRoaXMuY2hlY2tUaXRsZShpdGVtLCBpc0FnZW50cywgdGFiKTtcbiAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJ3NwbGl0c2luZ2xldmlzJyArIHRpdGxlWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgICAgICB0ZXh0OiB0aXRsZVswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgICB3aWR0aDogMjgwXG4gICAgICAgICAgfVxuICAgICAgICBdXG4gICAgICB9KTtcbiAgICAgIHRoaXMuYWRkQ29udGVudCh7IGNvbHVtbnM6IFt7IGltYWdlOiBpdGVtLmVsZW1lbnQsIHdpZHRoOiAyODAgfV0gfSk7XG4gICAgICB0aGlzLmFkZE5ld0xpbmUoKTtcbiAgICB9XG4gIH1cbiAgZm9ybWF0RGF0ZShkYXRlOiBEYXRlKTogc3RyaW5nIHtcbiAgICBsb2coJ3JlcG9ydGluZzpmb3JtYXREYXRlJywgYEZvcm1hdCBkYXRlICR7ZGF0ZX1gLCAnaW5mbycpO1xuICAgIGNvbnN0IHllYXIgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgY29uc3QgbW9udGggPSBkYXRlLmdldE1vbnRoKCkgKyAxO1xuICAgIGNvbnN0IGRheSA9IGRhdGUuZ2V0RGF0ZSgpO1xuICAgIGNvbnN0IGhvdXJzID0gZGF0ZS5nZXRIb3VycygpO1xuICAgIGNvbnN0IG1pbnV0ZXMgPSBkYXRlLmdldE1pbnV0ZXMoKTtcbiAgICBjb25zdCBzZWNvbmRzID0gZGF0ZS5nZXRTZWNvbmRzKCk7XG4gICAgY29uc3Qgc3RyID0gYCR7eWVhcn0tJHttb250aCA8IDEwID8gJzAnICsgbW9udGggOiBtb250aH0tJHtcbiAgICAgIGRheSA8IDEwID8gJzAnICsgZGF5IDogZGF5XG4gICAgfVQke2hvdXJzIDwgMTAgPyAnMCcgKyBob3VycyA6IGhvdXJzfToke1xuICAgICAgbWludXRlcyA8IDEwID8gJzAnICsgbWludXRlcyA6IG1pbnV0ZXNcbiAgICB9OiR7c2Vjb25kcyA8IDEwID8gJzAnICsgc2Vjb25kcyA6IHNlY29uZHN9YDtcbiAgICBsb2coJ3JlcG9ydGluZzpmb3JtYXREYXRlJywgYHN0cjogJHtzdHJ9YCwgJ2RlYnVnJyk7XG4gICAgcmV0dXJuIHN0cjtcbiAgfVxuICBjaGVja1RpdGxlKGl0ZW0sIGlzQWdlbnRzLCB0YWIpIHtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOmNoZWNrVGl0bGUnLFxuICAgICAgYEl0ZW0gSUQgJHtpdGVtLmlkfSwgZnJvbSAke1xuICAgICAgICBpc0FnZW50cyA/ICdhZ2VudHMnIDogJ292ZXJ2aWV3J1xuICAgICAgfSBhbmQgdGFiICR7dGFifWAsXG4gICAgICAnaW5mbydcbiAgICApO1xuXG4gICAgY29uc3QgdGl0bGUgPSBpc0FnZW50c1xuICAgICAgPyBBZ2VudHNWaXN1YWxpemF0aW9uc1t0YWJdLmZpbHRlcih2ID0+IHYuX2lkID09PSBpdGVtLmlkKVxuICAgICAgOiBPdmVydmlld1Zpc3VhbGl6YXRpb25zW3RhYl0uZmlsdGVyKHYgPT4gdi5faWQgPT09IGl0ZW0uaWQpO1xuICAgIHJldHVybiB0aXRsZTtcbiAgfVxuXG4gIGFkZFNpbXBsZVRhYmxlKHtjb2x1bW5zLCBpdGVtcywgdGl0bGV9OiB7Y29sdW1uczogKHtpZDogc3RyaW5nLCBsYWJlbDogc3RyaW5nfSlbXSwgdGl0bGU/OiAoc3RyaW5nIHwge3RleHQ6IHN0cmluZywgc3R5bGU6IHN0cmluZ30pLCBpdGVtczogYW55W119KXtcblxuICAgIGlmICh0aXRsZSkge1xuICAgICAgdGhpcy5hZGRDb250ZW50KHR5cGVvZiB0aXRsZSA9PT0gJ3N0cmluZycgPyB7IHRleHQ6IHRpdGxlLCBzdHlsZTogJ2g0JyB9IDogdGl0bGUpXG4gICAgICAgIC5hZGROZXdMaW5lKCk7XG4gICAgfVxuICBcbiAgICBpZiAoIWl0ZW1zIHx8ICFpdGVtcy5sZW5ndGgpIHtcbiAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgIHRleHQ6ICdObyByZXN1bHRzIG1hdGNoIHlvdXIgc2VhcmNoIGNyaXRlcmlhJyxcbiAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCdcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuXG4gICAgY29uc3QgdGFibGVIZWFkZXIgPSBjb2x1bW5zLm1hcChjb2x1bW4gPT4ge1xuICAgICAgcmV0dXJuIHsgdGV4dDogY29sdW1uLmxhYmVsLCBzdHlsZTogJ3doaXRlQ29sb3InLCBib3JkZXI6IFswLCAwLCAwLCAwXSB9O1xuICAgIH0pO1xuXG4gICAgY29uc3QgdGFibGVSb3dzID0gaXRlbXMubWFwKChpdGVtLCBpbmRleCkgPT4ge1xuICAgICAgcmV0dXJuIGNvbHVtbnMubWFwKGNvbHVtbiA9PiB7XG4gICAgICAgIGNvbnN0IGNlbGxWYWx1ZSA9IGl0ZW1bY29sdW1uLmlkXTtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICB0ZXh0OiB0eXBlb2YgY2VsbFZhbHVlICE9PSAndW5kZWZpbmVkJyA/IGNlbGxWYWx1ZSA6ICctJyxcbiAgICAgICAgICBzdHlsZTogJ3N0YW5kYXJkJ1xuICAgICAgICB9XG4gICAgICB9KVxuICAgIH0pO1xuICBcbiAgICBjb25zdCB3aWR0aHMgPSBuZXcgQXJyYXkoY29sdW1ucy5sZW5ndGggLSAxKS5maWxsKCdhdXRvJyk7XG4gICAgd2lkdGhzLnB1c2goJyonKTtcbiAgXG4gICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgIGZvbnRTaXplOiA4LFxuICAgICAgdGFibGU6IHtcbiAgICAgICAgaGVhZGVyUm93czogMSxcbiAgICAgICAgd2lkdGhzLFxuICAgICAgICBib2R5OiBbdGFibGVIZWFkZXIsIC4uLnRhYmxlUm93c11cbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZmlsbENvbG9yOiBpID0+IChpID09PSAwID8gQ09MT1JTLlBSSU1BUlkgOiBudWxsKSxcbiAgICAgICAgaExpbmVDb2xvcjogKCkgPT4gQ09MT1JTLlBSSU1BUlksXG4gICAgICAgIGhMaW5lV2lkdGg6ICgpID0+IDEsXG4gICAgICAgIHZMaW5lV2lkdGg6ICgpID0+IDBcbiAgICAgIH1cbiAgICB9KS5hZGROZXdMaW5lKCk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBhZGRMaXN0KHt0aXRsZSwgbGlzdH06IHt0aXRsZTogc3RyaW5nIHwge3RleHQ6IHN0cmluZywgc3R5bGU6IHN0cmluZ30sIGxpc3Q6IChzdHJpbmcgfCB7dGV4dDogc3RyaW5nLCBzdHlsZTogc3RyaW5nfSlbXX0pe1xuICAgIHJldHVybiB0aGlzXG4gICAgICAuYWRkQ29udGVudFdpdGhOZXdMaW5lKHR5cGVvZiB0aXRsZSA9PT0gJ3N0cmluZycgPyB7dGV4dDogdGl0bGUsIHN0eWxlOiAnaDInfSA6IHRpdGxlKVxuICAgICAgLmFkZENvbnRlbnQoe3VsOiBsaXN0LmZpbHRlcihlbGVtZW50ID0+IGVsZW1lbnQpfSlcbiAgICAgIC5hZGROZXdMaW5lKCk7XG4gIH1cblxuICBhZGROZXdMaW5lKCl7XG4gICAgcmV0dXJuIHRoaXMuYWRkQ29udGVudCh7dGV4dDogJ1xcbid9KTtcbiAgfVxuXG4gIGFkZENvbnRlbnRXaXRoTmV3TGluZSh0aXRsZTogYW55KXtcbiAgICByZXR1cm4gdGhpcy5hZGRDb250ZW50KHRpdGxlKS5hZGROZXdMaW5lKCk7XG4gIH1cblxuICBhZGRBZ2VudHNGaWx0ZXJzKGFnZW50cyl7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzphZGRBZ2VudHNGaWx0ZXJzJyxcbiAgICAgIGBTdGFydGVkIHRvIHJlbmRlciB0aGUgYXV0aG9yaXplZCBhZ2VudHMgZmlsdGVyc2AsXG4gICAgICAnaW5mbydcbiAgICApO1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6YWRkQWdlbnRzRmlsdGVycycsXG4gICAgICBgYWdlbnRzOiAke2FnZW50c31gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gICAgXG4gICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgXG4gICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgIHRleHQ6XG4gICAgICAgICdOT1RFOiBUaGlzIHJlcG9ydCBvbmx5IGluY2x1ZGVzIHRoZSBhdXRob3JpemVkIGFnZW50cyBvZiB0aGUgdXNlciB3aG8gZ2VuZXJhdGVkIHRoZSByZXBvcnQnLFxuICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDEwLCBjb2xvcjogQ09MT1JTLlBSSU1BUlkgfSxcbiAgICAgIG1hcmdpbjogWzAsIDAsIDAsIDVdXG4gICAgfSk7XG5cbiAgICAvKlRPRE86IFRoaXMgd2lsbCBiZSBlbmFibGVkIGJ5IGEgY29uZmlnKi9cbiAgICAvKiB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgZm9udFNpemU6IDgsXG4gICAgICB0YWJsZToge1xuICAgICAgICB3aWR0aHM6IFsnKiddLFxuICAgICAgICBib2R5OiBbXG4gICAgICAgICAgW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgc3ZnOiBmaWx0ZXJJY29uUmF3LFxuICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwLFxuICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMCxcbiAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzQwLCA2LCAwLCAwXVxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgdGV4dDogYEFnZW50IElEczogJHthZ2VudHN9YCB8fCAnLScsXG4gICAgICAgICAgICAgICAgICBtYXJnaW46IFs0MywgMCwgMCwgMF0sXG4gICAgICAgICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogOCwgY29sb3I6ICcjMzMzJyB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBdXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICBdXG4gICAgICB9LFxuICAgICAgbWFyZ2luOiBbLTQwLCAwLCAtNDAsIDBdLFxuICAgICAgbGF5b3V0OiB7XG4gICAgICAgIGZpbGxDb2xvcjogKCkgPT4gbnVsbCxcbiAgICAgICAgaExpbmVXaWR0aDogKCkgPT4gMCxcbiAgICAgICAgdkxpbmVXaWR0aDogKCkgPT4gMFxuICAgICAgfVxuICAgIH0pOyAqL1xuXG4gICAgdGhpcy5hZGRDb250ZW50KHsgdGV4dDogJ1xcbicgfSk7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzphZGRBZ2VudHNGaWx0ZXJzJyxcbiAgICAgICdUaW1lIHJhbmdlIGFuZCBmaWx0ZXJzIHJlbmRlcmVkJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICB9XG5cbiAgYXN5bmMgcHJpbnQocGF0aDogc3RyaW5nKXtcbiAgICBjb25zdCBkb2N1bWVudCA9IHRoaXMuX3ByaW50ZXIuY3JlYXRlUGRmS2l0RG9jdW1lbnQoey4uLnBhZ2VDb25maWd1cmF0aW9uLCBjb250ZW50OiB0aGlzLl9jb250ZW50fSk7XG4gICAgYXdhaXQgZG9jdW1lbnQucGlwZShcbiAgICAgIGZzLmNyZWF0ZVdyaXRlU3RyZWFtKHBhdGgpXG4gICAgKTtcbiAgICBkb2N1bWVudC5lbmQoKTtcbiAgfVxuXG59Il19