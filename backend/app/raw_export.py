"""Generate an Excel workbook from a saved per-run raw collection snapshot.

Uses only Python's standard library, compatible with the server's Python 3.9
and no extra Excel dependency. Text is stored as inline strings (not formulas).
"""
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from xml.sax.saxutils import escape
import re

HEADERS = [
    "序号", "运行编号", "来源", "采集方式", "内容类型", "采集器CVE",
    "正文识别的全部CVE", "CVE差异提醒", "标题", "当前等级", "原始等级",
    "披露时间", "原始链接", "处理结果", "过滤原因", "描述", "修复建议", "原始JSON",
]
COLUMNS = [
    "id", "run_id", "source", "source_type", "content_type", "cve",
    "title", "severity", "original_severity", "disclosure", "url",
    "outcome", "reason", "description", "solutions", "payload",
]
WIDTHS = [10, 12, 25, 15, 15, 23, 35, 19, 65, 15, 15, 23, 60, 22, 40, 85, 70, 90]
MAX_EXCEL_CHARS = 32767
MAX_ROWS_PER_SHEET = 1048575
_INVALID_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _safe(value):
    # Excel maximum cell length. Remove XML-invalid control characters.
    value = _INVALID_XML.sub("", str(value if value is not None else ""))
    return value[:MAX_EXCEL_CHARS]


def _column_name(n):
    out = ""
    while n:
        n, mod = divmod(n - 1, 26)
        out = chr(65 + mod) + out
    return out


def _cell(column, row, value, style=0):
    address = _column_name(column) + str(row)
    value = escape(_safe(value), {'"': '&quot;'})
    return ('<c r="%s" s="%d" t="inlineStr"><is><t xml:space="preserve">%s'
            '</t></is></c>' % (address, style, value))


def _sheet(rows, data_rows=True):
    output = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
              '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
              '<sheetViews><sheetView workbookViewId="0">'
              '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
              '</sheetView></sheetViews>']
    if data_rows:
        output.append('<cols>')
        for i, width in enumerate(WIDTHS, 1):
            output.append('<col min="%d" max="%d" width="%d" customWidth="1"/>'
                          % (i, i, width))
        output.append('</cols>')
    output.append('<sheetData>')
    for row_index, row_values in enumerate(rows, 1):
        style = 1 if row_index == 1 else 2 if row_index % 2 == 0 else 0
        output.append('<row r="%d">' % row_index)
        for column_index, value in enumerate(row_values, 1):
            output.append(_cell(column_index, row_index, value, style))
        output.append('</row>')
    output.append('</sheetData>')
    if data_rows:
        output.append('<autoFilter ref="A1:R%d"/>' % max(1, len(rows)))
    output.append('</worksheet>')
    return "".join(output).encode("utf-8")


def build_raw_collection_xlsx(records, run_id, mode):
    """One row for every parsed upstream result, including filtered results."""
    values = []
    for n, record in enumerate(records, 1):
        data={column:getattr(record,column,"") for column in COLUMNS}
        all_cves=[]
        for value in (data["title"],data["description"],data["payload"]):
            for match in re.findall(r"CVE-\d{4}-\d{4,}",str(value or ""),re.IGNORECASE):
                value=match.upper()
                if value not in all_cves:
                    all_cves.append(value)
        parsed={v.upper() for v in re.findall(r"CVE-\d{4}-\d{4,}",str(data["cve"] or ""),re.IGNORECASE)}
        additional=[code for code in all_cves if code not in parsed]
        hint=("需检查：" + ", ".join(additional)) if additional else ""
        values.append([
            n,data["run_id"],data["source"],data["source_type"],data["content_type"],
            data["cve"],", ".join(all_cves),hint,data["title"],data["severity"],
            data["original_severity"],data["disclosure"],data["url"],data["outcome"],
            data["reason"],data["description"],data["solutions"],data["payload"],
        ])
    sheets = []
    # Split only if the Excel worksheet row limit is reached.
    for start in range(0, len(values), MAX_ROWS_PER_SHEET):
        subset = values[start:start + MAX_ROWS_PER_SHEET]
        sheets.append((("原始采集" if not sheets else "原始采集%d" % (len(sheets) + 1)),
                       _sheet([HEADERS] + subset)))
    if not sheets:
        sheets.append(("原始采集", _sheet([HEADERS])))
    notes = [
        ["项目", "说明"],
        ["运行编号", run_id],
        ["采集类型", mode],
        ["统计数量", len(values)],
        ["数据口径", "RSS 已解析条目和 Python 爬虫 stdout items；按本次运行合并，不做 CVE 去重。"],
        ["过滤前数据", "进入等级、关键词、日期及去重判断前持久化，包括过滤及重复记录。"],
        ["当前等级", "可能经过 NVD 等级补齐；原始等级保留首次接收时的值。"],
        ["处理结果", "记录当时规则判断；部分上游异常或处理失败的条目可能显示未处理。"],
        ["CVE 校验", "采集器CVE与正文识别的全部CVE并列，CVE差异提醒提示同条情报中可能遗漏的其他CVE；须人工核实。"],
        ["不包含", "RSS 解析器跳过的无标题项目、源站未返回的项目以及未成功输出合法 JSON 的脚本。"],
        ["历史记录", "启用本功能以前的运行无法补回当时未保存的原始结果。"],
        ["Excel 限制", "单元格文本最多 32767 字符，超出部分在 Excel 中截断。"],
    ]
    sheets.append(("说明", _sheet(notes, data_rows=False)))
    workbook = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
        '<sheets>',
    ]
    for i, (name, _) in enumerate(sheets, 1):
        workbook.append('<sheet name="%s" sheetId="%d" r:id="rId%d"/>'
                        % (escape(name), i, i))
    workbook.append('</sheets></workbook>')
    relations = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
    ]
    for i in range(1, len(sheets) + 1):
        relations.append('<Relationship Id="rId%d" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            'Target="worksheets/sheet%d.xml"/>' % (i, i))
    relations.append('<Relationship Id="rId%d" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>' % (len(sheets) + 1))
    relations.append('</Relationships>')
    content_types = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    for i in range(1, len(sheets) + 1):
        content_types.append('<Override PartName="/xl/worksheets/sheet%d.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            % i)
    content_types.append('</Types>')
    style_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="10"/><name val="Calibri"/></font>'
        '<font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Calibri"/></font></fonts>'
        '<fills count="3"><fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF17365D"/>'
        '<bgColor indexed="64"/></patternFill></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="3">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFill="1" applyFont="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '</cellXfs></styleSheet>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    )
    target = BytesIO()
    with ZipFile(target, "w", ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("[Content_Types].xml", "".join(content_types))
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", "".join(workbook))
        archive.writestr("xl/_rels/workbook.xml.rels", "".join(relations))
        archive.writestr("xl/styles.xml", style_xml)
        for i, (_, sheet_xml) in enumerate(sheets, 1):
            archive.writestr("xl/worksheets/sheet%d.xml" % i, sheet_xml)
    return target.getvalue()
