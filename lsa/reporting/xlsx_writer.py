"""Minimal, dependency-free Office Open XML (xlsx) writer.

Supports what the assessment workbooks need: shared strings, fonts, fills,
alignment and number formats, merged cells, column widths, row heights,
frozen panes, Excel tables with autofilter, expression-based conditional
formatting, external hyperlinks and a clustered bar chart.

Every text value is written as a shared string, never as a formula, so
host-controlled text such as a file name beginning with '=' cannot execute
when the workbook is opened. Characters that are illegal in XML are removed
and cells are capped at Excel's 32,767 character limit.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

try:  # Minimal interpreters (such as some embedded builds) may lack zlib.
    import zlib  # noqa: F401

    _COMPRESSION = zipfile.ZIP_DEFLATED
except ImportError:
    _COMPRESSION = zipfile.ZIP_STORED

CELL_LIMIT = 32_767
ILLEGAL_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")
EXCEL_EPOCH = datetime(1899, 12, 30)
EMU_PER_CM = 360_000

NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_BASE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def clean_text(value: Any) -> str:
    text = ILLEGAL_XML.sub("", str(value))
    return text[:CELL_LIMIT]


def column_letter(index: int) -> str:
    letters = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def cell_ref(row: int, column: int) -> str:
    return f"{column_letter(column)}{row}"


def _argb(color: str | None) -> str | None:
    if not color:
        return None
    color = color.lstrip("#").upper()
    return color if len(color) == 8 else "FF" + color


@dataclass(frozen=True)
class Style:
    bold: bool = False
    italic: bool = False
    underline: bool = False
    color: str | None = None
    size: float = 11
    fill: str | None = None
    wrap: bool = False
    vertical: str | None = None
    horizontal: str | None = None
    number_format: str | None = None


class _Styles:
    BUILTIN_FORMATS = {"General": 0, "0": 1, "0.00": 2, "0%": 9, "0.00%": 10}

    def __init__(self) -> None:
        self.fonts: list[str] = [self._font(Style())]
        self.fills: list[str] = ['<fill><patternFill patternType="none"/></fill>', '<fill><patternFill patternType="gray125"/></fill>']
        self.formats: dict[str, int] = {}
        self.xfs: list[str] = ['<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>']
        self.index: dict[Style, int] = {Style(): 0}
        self.dxfs: list[str] = []

    @staticmethod
    def _font(style: Style) -> str:
        parts = ["<font>"]
        if style.bold:
            parts.append("<b/>")
        if style.italic:
            parts.append("<i/>")
        if style.underline:
            parts.append('<u val="single"/>')
        parts.append(f'<sz val="{style.size:g}"/>')
        if style.color:
            parts.append(f'<color rgb="{_argb(style.color)}"/>')
        else:
            parts.append('<color theme="1"/>')
        parts.append('<name val="Calibri"/><family val="2"/><scheme val="minor"/></font>')
        return "".join(parts)

    def xf(self, style: Style | None) -> int:
        if style is None:
            return 0
        if style in self.index:
            return self.index[style]
        font_xml = self._font(style)
        if font_xml not in self.fonts:
            self.fonts.append(font_xml)
        font_id = self.fonts.index(font_xml)
        fill_id = 0
        if style.fill:
            fill_xml = f'<fill><patternFill patternType="solid"><fgColor rgb="{_argb(style.fill)}"/><bgColor indexed="64"/></patternFill></fill>'
            if fill_xml not in self.fills:
                self.fills.append(fill_xml)
            fill_id = self.fills.index(fill_xml)
        number_id = 0
        if style.number_format:
            number_id = self.BUILTIN_FORMATS.get(style.number_format)
            if number_id is None:
                number_id = self.formats.setdefault(style.number_format, 164 + len(self.formats))
        attributes = f'numFmtId="{number_id}" fontId="{font_id}" fillId="{fill_id}" borderId="0" xfId="0"'
        attributes += ' applyFont="1"' if font_id else ""
        attributes += ' applyFill="1"' if fill_id else ""
        attributes += ' applyNumberFormat="1"' if number_id else ""
        alignment = ""
        if style.wrap or style.vertical or style.horizontal:
            attrs = []
            if style.horizontal:
                attrs.append(f'horizontal="{style.horizontal}"')
            if style.vertical:
                attrs.append(f'vertical="{style.vertical}"')
            if style.wrap:
                attrs.append('wrapText="1"')
            alignment = f"<alignment {' '.join(attrs)}/>"
            attributes += ' applyAlignment="1"'
        self.xfs.append(f"<xf {attributes}>{alignment}</xf>" if alignment else f"<xf {attributes}/>")
        self.index[style] = len(self.xfs) - 1
        return self.index[style]

    def dxf(self, fill: str, font_color: str | None = None, bold: bool = False) -> int:
        font = ""
        if font_color or bold:
            font = "<font>" + ("<b/>" if bold else "") + (f'<color rgb="{_argb(font_color)}"/>' if font_color else "") + "</font>"
        xml = f'<dxf>{font}<fill><patternFill patternType="solid"><bgColor rgb="{_argb(fill)}"/></patternFill></fill></dxf>'
        if xml not in self.dxfs:
            self.dxfs.append(xml)
        return self.dxfs.index(xml)

    def xml(self) -> str:
        parts = [f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="{NS_MAIN}">']
        if self.formats:
            parts.append(f'<numFmts count="{len(self.formats)}">')
            parts.extend(f'<numFmt numFmtId="{number}" formatCode="{escape(code, {chr(34): "&quot;"})}"/>' for code, number in self.formats.items())
            parts.append("</numFmts>")
        parts.append(f'<fonts count="{len(self.fonts)}">{"".join(self.fonts)}</fonts>')
        parts.append(f'<fills count="{len(self.fills)}">{"".join(self.fills)}</fills>')
        parts.append('<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>')
        parts.append('<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>')
        parts.append(f'<cellXfs count="{len(self.xfs)}">{"".join(self.xfs)}</cellXfs>')
        parts.append('<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>')
        parts.append(f'<dxfs count="{len(self.dxfs)}">{"".join(self.dxfs)}</dxfs>')
        parts.append('<tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>')
        parts.append("</styleSheet>")
        return "".join(parts)


@dataclass
class _Table:
    name: str
    first_row: int
    first_col: int
    last_row: int
    last_col: int
    style: str


@dataclass
class _Chart:
    anchor_row: int
    anchor_col: int
    title: str
    y_title: str
    series_ref: tuple[int, int]
    categories: tuple[int, int, int]
    values: tuple[int, int, int]
    width_cm: float
    height_cm: float
    color: str


class Worksheet:
    def __init__(self, workbook: Workbook, title: str) -> None:
        if len(title) > 31 or re.search(r"[\[\]:*?/\\]", title):
            raise ValueError(f"Invalid worksheet title '{title}'")
        self.workbook = workbook
        self.title = title
        self.cells: dict[tuple[int, int], tuple[Any, int]] = {}
        self.merges: list[str] = []
        self.widths: dict[int, float] = {}
        self.heights: dict[int, float] = {}
        self.freeze: str | None = None
        self.tables: list[_Table] = []
        self.conditional: list[tuple[str, str, int]] = []
        self.links: list[tuple[str, str]] = []
        self.charts: list[_Chart] = []

    @property
    def max_row(self) -> int:
        return max((row for row, _ in self.cells), default=0)

    def set(self, row: int, column: int, value: Any, style: Style | None = None) -> None:
        self.cells[(row, column)] = (value, self.workbook.styles.xf(style))

    def restyle(self, row: int, column: int, style: Style) -> None:
        value = self.cells.get((row, column), (None, 0))[0]
        self.set(row, column, value, style)

    def value(self, row: int, column: int) -> Any:
        return self.cells.get((row, column), (None, 0))[0]

    def append(self, values: list[Any], style: Style | None = None) -> int:
        row = self.max_row + 1
        for column, value in enumerate(values, 1):
            self.set(row, column, value, style)
        return row

    def merge(self, first_row: int, first_col: int, last_row: int, last_col: int) -> None:
        self.merges.append(f"{cell_ref(first_row, first_col)}:{cell_ref(last_row, last_col)}")

    def width(self, column: int, width: float) -> None:
        self.widths[column] = width

    def height(self, row: int, height: float) -> None:
        self.heights[row] = height

    def add_table(self, name: str, first_row: int, first_col: int, last_row: int, last_col: int, style: str = "TableStyleMedium2") -> None:
        self.tables.append(_Table(name, first_row, first_col, last_row, last_col, style))

    def add_conditional_fill(self, ref: str, formula: str, fill: str, font_color: str | None = None) -> None:
        self.conditional.append((ref, formula, self.workbook.styles.dxf(fill, font_color)))

    def add_hyperlink(self, row: int, column: int, url: str) -> None:
        self.links.append((cell_ref(row, column), url))

    def add_bar_chart(
        self,
        anchor: tuple[int, int],
        title: str,
        y_title: str,
        series_title: tuple[int, int],
        categories: tuple[int, int, int],
        values: tuple[int, int, int],
        width_cm: float = 13,
        height_cm: float = 7,
        color: str = "0B6E99",
    ) -> None:
        self.charts.append(_Chart(anchor[0], anchor[1], title, y_title, series_title, categories, values, width_cm, height_cm, color))

    # ------------------------------------------------------------- xml
    def _cell_xml(self, row: int, column: int, value: Any, style_id: int) -> str:
        ref = cell_ref(row, column)
        style = f' s="{style_id}"' if style_id else ""
        if value is None or value == "":
            return f'<c r="{ref}"{style}/>' if style_id else ""
        if isinstance(value, bool):
            return f'<c r="{ref}"{style} t="b"><v>{int(value)}</v></c>'
        if isinstance(value, (int, float)):
            return f'<c r="{ref}"{style}><v>{value!r}</v></c>'
        if isinstance(value, datetime):
            if value.tzinfo is not None:
                value = value.astimezone(timezone.utc).replace(tzinfo=None)
            serial = (value - EXCEL_EPOCH).total_seconds() / 86400
            return f'<c r="{ref}"{style}><v>{serial:.8f}</v></c>'
        index = self.workbook.shared_string(clean_text(value))
        return f'<c r="{ref}"{style} t="s"><v>{index}</v></c>'

    def xml(self, sheet_index: int, rels: list[tuple[str, str, str | None]]) -> str:
        parts = [f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="{NS_MAIN}" xmlns:r="{NS_REL}">']
        max_row = max(self.max_row, 1)
        max_col = max((column for _, column in self.cells), default=1)
        parts.append(f'<dimension ref="A1:{cell_ref(max_row, max_col)}"/>')
        selected = ' tabSelected="1"' if sheet_index == 1 else ""
        if self.freeze:
            match = re.match(r"([A-Z]+)(\d+)", self.freeze)
            split_row = int(match.group(2)) - 1 if match else 0
            parts.append(
                f'<sheetViews><sheetView workbookViewId="0"{selected}><pane ySplit="{split_row}" topLeftCell="{self.freeze}" '
                f'activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="{self.freeze}" sqref="{self.freeze}"/>'
                "</sheetView></sheetViews>"
            )
        else:
            parts.append(f'<sheetViews><sheetView workbookViewId="0"{selected}/></sheetViews>')
        parts.append('<sheetFormatPr defaultRowHeight="15"/>')
        if self.widths:
            parts.append("<cols>")
            parts.extend(f'<col min="{c}" max="{c}" width="{w:g}" customWidth="1"/>' for c, w in sorted(self.widths.items()))
            parts.append("</cols>")
        parts.append("<sheetData>")
        rows: dict[int, list[tuple[int, Any, int]]] = {}
        for (row, column), (value, style_id) in self.cells.items():
            rows.setdefault(row, []).append((column, value, style_id))
        for row in sorted(set(rows) | set(self.heights)):
            height = self.heights.get(row)
            attributes = f' ht="{height:g}" customHeight="1"' if height else ""
            cells = "".join(self._cell_xml(row, column, value, style_id) for column, value, style_id in sorted(rows.get(row, []), key=lambda item: item[0]))
            parts.append(f'<row r="{row}"{attributes}>{cells}</row>')
        parts.append("</sheetData>")
        if self.merges:
            parts.append(f'<mergeCells count="{len(self.merges)}">' + "".join(f'<mergeCell ref="{ref}"/>' for ref in self.merges) + "</mergeCells>")
        priority = 1
        for ref, formula, dxf_id in self.conditional:
            parts.append(
                f'<conditionalFormatting sqref="{ref}"><cfRule type="expression" dxfId="{dxf_id}" priority="{priority}">'
                f"<formula>{escape(formula)}</formula></cfRule></conditionalFormatting>"
            )
            priority += 1
        if self.links:
            parts.append("<hyperlinks>")
            for ref, url in self.links:
                rel_id = f"rId{len(rels) + 1}"
                rels.append((rel_id, f"{REL_BASE}/hyperlink", url))
                parts.append(f'<hyperlink ref="{ref}" r:id="{rel_id}"/>')
            parts.append("</hyperlinks>")
        parts.append('<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>')
        if self.charts:
            rel_id = f"rId{len(rels) + 1}"
            rels.append((rel_id, f"{REL_BASE}/drawing", f"../drawings/drawing{self.workbook.drawing_number(self)}.xml"))
            parts.append(f'<drawing r:id="{rel_id}"/>')
        if self.tables:
            parts.append(f'<tableParts count="{len(self.tables)}">')
            for table in self.tables:
                rel_id = f"rId{len(rels) + 1}"
                rels.append((rel_id, f"{REL_BASE}/table", f"../tables/table{self.workbook.table_number(table)}.xml"))
                parts.append(f'<tablePart r:id="{rel_id}"/>')
            parts.append("</tableParts>")
        parts.append("</worksheet>")
        return "".join(parts)


class Workbook:
    def __init__(self, creator: str = "linux-security-audit") -> None:
        self.creator = creator
        self.styles = _Styles()
        self.sheets: list[Worksheet] = []
        self._strings: dict[str, int] = {}
        self._string_list: list[str] = []
        self._string_count = 0
        self._tables: list[tuple[Worksheet, _Table]] = []
        self._drawings: list[Worksheet] = []

    def add_sheet(self, title: str) -> Worksheet:
        sheet = Worksheet(self, title)
        self.sheets.append(sheet)
        return sheet

    def shared_string(self, text: str) -> int:
        self._string_count += 1
        if text not in self._strings:
            self._strings[text] = len(self._string_list)
            self._string_list.append(text)
        return self._strings[text]

    def table_number(self, table: _Table) -> int:
        for index, (_, item) in enumerate(self._tables, 1):
            if item is table:
                return index
        raise KeyError(table.name)

    def drawing_number(self, sheet: Worksheet) -> int:
        return self._drawings.index(sheet) + 1

    def _table_xml(self, sheet: Worksheet, table: _Table, number: int) -> str:
        ref = f"{cell_ref(table.first_row, table.first_col)}:{cell_ref(table.last_row, table.last_col)}"
        names = []
        for column in range(table.first_col, table.last_col + 1):
            name = clean_text(sheet.value(table.first_row, column) or f"Column{column}").replace("\n", " ")
            while name in names:
                name += "_"
            names.append(name)
        columns = "".join(f'<tableColumn id="{i}" name="{escape(n, {chr(34): "&quot;"})}"/>' for i, n in enumerate(names, 1))
        return (
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><table xmlns="{NS_MAIN}" id="{number}" name="{table.name}" '
            f'displayName="{table.name}" ref="{ref}" totalsRowShown="0"><autoFilter ref="{ref}"/>'
            f'<tableColumns count="{len(names)}">{columns}</tableColumns>'
            f'<tableStyleInfo name="{table.style}" showFirstColumn="0" showLastColumn="0" showRowStripes="1" showColumnStripes="0"/></table>'
        )

    @staticmethod
    def _range(sheet: Worksheet, column: int, first: int, last: int) -> str:
        name = sheet.title.replace("'", "''")
        letter = column_letter(column)
        return f"'{name}'!${letter}${first}:${letter}${last}"

    def _chart_xml(self, sheet: Worksheet, chart: _Chart) -> str:
        category_col, category_first, category_last = chart.categories
        value_col, value_first, value_last = chart.values
        series_row, series_col = chart.series_ref
        categories = [clean_text(sheet.value(row, category_col) or "") for row in range(category_first, category_last + 1)]
        values = [sheet.value(row, value_col) or 0 for row in range(value_first, value_last + 1)]
        series_name = clean_text(sheet.value(series_row, series_col) or "")
        sheet_name = sheet.title.replace("'", "''")
        category_cache = "".join(f'<c:pt idx="{i}"><c:v>{escape(v)}</c:v></c:pt>' for i, v in enumerate(categories))
        value_cache = "".join(f'<c:pt idx="{i}"><c:v>{v}</c:v></c:pt>' for i, v in enumerate(values))

        def title(text: str, rotate: bool = False) -> str:
            body = '<a:bodyPr rot="-5400000" vert="horz"/>' if rotate else "<a:bodyPr/>"
            return f'<c:title><c:tx><c:rich>{body}<a:p><a:r><a:t>{escape(text)}</a:t></a:r></a:p></c:rich></c:tx><c:overlay val="0"/></c:title>'

        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            f'xmlns:r="{NS_REL}"><c:roundedCorners val="0"/><c:chart>{title(chart.title)}<c:autoTitleDeleted val="0"/>'
            '<c:plotArea><c:layout/><c:barChart><c:barDir val="col"/><c:grouping val="clustered"/><c:varyColors val="0"/>'
            '<c:ser><c:idx val="0"/><c:order val="0"/>'
            f"<c:tx><c:strRef><c:f>'{sheet_name}'!${column_letter(series_col)}${series_row}</c:f>"
            f'<c:strCache><c:ptCount val="1"/><c:pt idx="0"><c:v>{escape(series_name)}</c:v></c:pt></c:strCache></c:strRef></c:tx>'
            f'<c:spPr><a:solidFill><a:srgbClr val="{chart.color}"/></a:solidFill></c:spPr><c:invertIfNegative val="0"/>'
            f"<c:cat><c:strRef><c:f>{self._range(sheet, category_col, category_first, category_last)}</c:f>"
            f'<c:strCache><c:ptCount val="{len(categories)}"/>{category_cache}</c:strCache></c:strRef></c:cat>'
            f"<c:val><c:numRef><c:f>{self._range(sheet, value_col, value_first, value_last)}</c:f>"
            f'<c:numCache><c:formatCode>General</c:formatCode><c:ptCount val="{len(values)}"/>{value_cache}</c:numCache></c:numRef></c:val>'
            '</c:ser><c:gapWidth val="150"/><c:axId val="10"/><c:axId val="100"/></c:barChart>'
            '<c:catAx><c:axId val="10"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="b"/>'
            '<c:numFmt formatCode="General" sourceLinked="1"/><c:majorTickMark val="none"/><c:minorTickMark val="none"/>'
            '<c:tickLblPos val="nextTo"/><c:crossAx val="100"/><c:crosses val="autoZero"/><c:auto val="1"/><c:lblAlgn val="ctr"/>'
            '<c:lblOffset val="100"/><c:noMultiLvlLbl val="0"/></c:catAx>'
            '<c:valAx><c:axId val="100"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="l"/>'
            f'<c:majorGridlines/>{title(chart.y_title, rotate=True)}<c:numFmt formatCode="General" sourceLinked="1"/>'
            '<c:majorTickMark val="none"/><c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/><c:crossAx val="10"/>'
            '<c:crosses val="autoZero"/><c:crossBetween val="between"/></c:valAx></c:plotArea>'
            '<c:legend><c:legendPos val="r"/><c:overlay val="0"/></c:legend><c:plotVisOnly val="1"/><c:dispBlanksAs val="gap"/>'
            "</c:chart></c:chartSpace>"
        )

    @staticmethod
    def _drawing_xml(sheet: Worksheet) -> str:
        anchors = []
        for index, chart in enumerate(sheet.charts, 1):
            anchors.append(
                f"<xdr:oneCellAnchor><xdr:from><xdr:col>{chart.anchor_col - 1}</xdr:col><xdr:colOff>0</xdr:colOff>"
                f"<xdr:row>{chart.anchor_row - 1}</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>"
                f'<xdr:ext cx="{int(chart.width_cm * EMU_PER_CM)}" cy="{int(chart.height_cm * EMU_PER_CM)}"/>'
                f'<xdr:graphicFrame macro=""><xdr:nvGraphicFramePr><xdr:cNvPr id="{index + 1}" name="Chart {index}"/>'
                "<xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr><xdr:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/></xdr:xfrm>"
                '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">'
                f'<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:r="{NS_REL}" r:id="rId{index}"/>'
                "</a:graphicData></a:graphic></xdr:graphicFrame><xdr:clientData/></xdr:oneCellAnchor>"
            )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">' + "".join(anchors) + "</xdr:wsDr>"
        )

    @staticmethod
    def _rels_xml(rels: list[tuple[str, str, str | None]]) -> str:
        items = []
        for rel_id, rel_type, target in rels:
            external = ' TargetMode="External"' if rel_type.endswith("/hyperlink") else ""
            items.append(f'<Relationship Id="{rel_id}" Type="{rel_type}" Target="{escape(str(target), {chr(34): "&quot;"})}"{external}/>')
        return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{NS_PKG_REL}">{"".join(items)}</Relationships>'

    def save(self, path: str) -> None:
        self._tables = [(sheet, table) for sheet in self.sheets for table in sheet.tables]
        self._drawings = [sheet for sheet in self.sheets if sheet.charts]
        sheet_xml: list[str] = []
        sheet_rels: list[list[tuple[str, str, str | None]]] = []
        for index, sheet in enumerate(self.sheets, 1):
            rels: list[tuple[str, str, str | None]] = []
            sheet_xml.append(sheet.xml(index, rels))
            sheet_rels.append(rels)
        overrides = [
            ("/xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
            ("/xl/styles.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"),
            ("/xl/sharedStrings.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"),
            ("/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
            ("/docProps/app.xml", "application/vnd.openxmlformats-officedocument.extended-properties+xml"),
        ]
        overrides += [(f"/xl/worksheets/sheet{i}.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml") for i in range(1, len(self.sheets) + 1)]
        overrides += [(f"/xl/tables/table{i}.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml") for i in range(1, len(self._tables) + 1)]
        overrides += [(f"/xl/drawings/drawing{i}.xml", "application/vnd.openxmlformats-officedocument.drawing+xml") for i in range(1, len(self._drawings) + 1)]
        chart_total = sum(len(sheet.charts) for sheet in self._drawings)
        overrides += [(f"/xl/charts/chart{i}.xml", "application/vnd.openxmlformats-officedocument.drawingml.chart+xml") for i in range(1, chart_total + 1)]
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            + "".join(f'<Override PartName="{part}" ContentType="{kind}"/>' for part, kind in overrides)
            + "</Types>"
        )
        workbook_rels = [(f"rId{i}", f"{REL_BASE}/worksheet", f"worksheets/sheet{i}.xml") for i in range(1, len(self.sheets) + 1)]
        workbook_rels.append((f"rId{len(self.sheets) + 1}", f"{REL_BASE}/styles", "styles.xml"))
        workbook_rels.append((f"rId{len(self.sheets) + 2}", f"{REL_BASE}/sharedStrings", "sharedStrings.xml"))
        sheets = "".join(f'<sheet name="{escape(s.title, {chr(34): "&quot;"})}" sheetId="{i}" r:id="rId{i}"/>' for i, s in enumerate(self.sheets, 1))
        workbook = (
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="{NS_MAIN}" xmlns:r="{NS_REL}">'
            f'<bookViews><workbookView activeTab="0"/></bookViews><sheets>{sheets}</sheets></workbook>'
        )
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        core = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:creator>{escape(self.creator)}</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified></cp:coreProperties>'
        )
        app = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties '
            'xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f"<Application>{escape(self.creator)}</Application></Properties>"
        )
        root_rels = self._rels_xml(
            [
                ("rId1", f"{REL_BASE}/officeDocument", "xl/workbook.xml"),
                ("rId2", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "docProps/core.xml"),
                ("rId3", f"{REL_BASE}/extended-properties", "docProps/app.xml"),
            ]
        )
        strings = "".join(f'<si><t xml:space="preserve">{escape(text)}</t></si>' for text in self._string_list)
        shared = (
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="{NS_MAIN}" '
            f'count="{self._string_count}" uniqueCount="{len(self._string_list)}">{strings}</sst>'
        )
        with zipfile.ZipFile(path, "w", _COMPRESSION) as archive:
            archive.writestr("[Content_Types].xml", content_types)
            archive.writestr("_rels/.rels", root_rels)
            archive.writestr("docProps/core.xml", core)
            archive.writestr("docProps/app.xml", app)
            archive.writestr("xl/workbook.xml", workbook)
            archive.writestr("xl/_rels/workbook.xml.rels", self._rels_xml(workbook_rels))
            archive.writestr("xl/styles.xml", self.styles.xml())
            for index, (xml, rels) in enumerate(zip(sheet_xml, sheet_rels), 1):
                archive.writestr(f"xl/worksheets/sheet{index}.xml", xml)
                if rels:
                    archive.writestr(f"xl/worksheets/_rels/sheet{index}.xml.rels", self._rels_xml(rels))
            for index, (sheet, table) in enumerate(self._tables, 1):
                archive.writestr(f"xl/tables/table{index}.xml", self._table_xml(sheet, table, index))
            chart_number = 0
            for index, sheet in enumerate(self._drawings, 1):
                archive.writestr(f"xl/drawings/drawing{index}.xml", self._drawing_xml(sheet))
                drawing_rels = []
                for position, chart in enumerate(sheet.charts, 1):
                    chart_number += 1
                    archive.writestr(f"xl/charts/chart{chart_number}.xml", self._chart_xml(sheet, chart))
                    drawing_rels.append((f"rId{position}", f"{REL_BASE}/chart", f"../charts/chart{chart_number}.xml"))
                archive.writestr(f"xl/drawings/_rels/drawing{index}.xml.rels", self._rels_xml(drawing_rels))
            archive.writestr("xl/sharedStrings.xml", shared)
