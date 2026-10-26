# Сборка PDF-отчёта по ЛР2
import json
from datetime import datetime
from html import escape
from pathlib import Path
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parent
WIDTH = A4[0] - 45 * mm
FONT = Path('/System/Library/Fonts/Supplemental')
pdfmetrics.registerFont(TTFont('TimesRU', str(FONT / 'Times New Roman.ttf')))
pdfmetrics.registerFont(TTFont('TimesRUBold', str(FONT / 'Times New Roman Bold.ttf')))
pdfmetrics.registerFontFamily('TimesRU', normal='TimesRU', bold='TimesRUBold', italic='TimesRU', boldItalic='TimesRUBold')
S = {
    'body': ParagraphStyle('body', fontName='TimesRU', fontSize=11, leading=14, alignment=TA_JUSTIFY, spaceAfter=6),
    'head': ParagraphStyle('head', fontName='TimesRUBold', fontSize=14, leading=18, spaceAfter=9),
    'sub': ParagraphStyle('sub', fontName='TimesRUBold', fontSize=12, leading=15, spaceBefore=7, spaceAfter=6),
    'small': ParagraphStyle('small', fontName='TimesRU', fontSize=10, leading=12, spaceAfter=5),
    'cell': ParagraphStyle('cell', fontName='TimesRU', fontSize=10, leading=12, alignment=TA_LEFT),
    'cap': ParagraphStyle('cap', fontName='TimesRU', fontSize=10, leading=12, alignment=TA_CENTER, spaceAfter=8),
    'center': ParagraphStyle('center', fontName='TimesRU', fontSize=13, leading=18, alignment=TA_CENTER, spaceAfter=10),
    'title': ParagraphStyle('title', fontName='TimesRUBold', fontSize=16, leading=22, alignment=TA_CENTER, spaceAfter=12),
    'right': ParagraphStyle('right', fontName='TimesRU', fontSize=12, leading=17, alignment=TA_RIGHT),
    'code': ParagraphStyle('code', fontName='Courier', fontSize=8.5, leading=11, backColor=colors.HexColor('#f1f3f5'), borderPadding=6, spaceBefore=4, spaceAfter=9),
}


def p(text, style='body'):
    return Paragraph(text, S[style])


def table(rows, ratios):
    item = Table([[p(escape(str(cell)), 'cell') for cell in row] for row in rows], colWidths=[WIDTH * ratio for ratio in ratios], repeatRows=1)
    item.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), .35, colors.HexColor('#a2aab3')), ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#eef1f4')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6), ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]))
    return item


def figure(name, caption, max_height=95):
    source = ROOT / 'screenshots' / name
    if not source.is_file():
        raise FileNotFoundError(f'Не снят настоящий Terminal: {source}')
    im = Image(str(source))
    factor = min(WIDTH / im.imageWidth, max_height * mm / im.imageHeight)
    im.drawWidth = im.imageWidth * factor
    im.drawHeight = im.imageHeight * factor
    return KeepTogether([im, Spacer(1, 4), p(caption, 'cap')])


def main():
    data = json.loads((ROOT / 'results.json').read_text())
    assert data['all_passed'] and all(data['checks'].values())
    assert data['cve'] == 'CVE-2021-43798'
    nvd = json.loads((ROOT / 'evidence/nvd-CVE-2021-43798.json').read_text())['vulnerabilities'][0]['cve']
    metrics = nvd['metrics']['cvssMetricV31']
    metric = next((m for m in metrics if m['type'] == 'Primary'), metrics[0])
    cvss = metric['cvssData']
    checked = datetime.fromisoformat(data['checked_at']).astimezone(ZoneInfo('Europe/Moscow')).strftime('%d.%m.%Y %H:%M МСК')
    vuln, fixed = data['environments']
    attack_path = vuln['traversal']['path']
    story = [p('Федеральное государственное автономное образовательное учреждение высшего образования<br/>«Национальный исследовательский университет ИТМО»', 'center'), Spacer(1, 57 * mm), p('Информационная безопасность', 'title'), p('Работа 2<br/>Анализ и устранение уязвимости на примере реального CVE с использованием Docker', 'title'), Spacer(1, 29 * mm), p('Евстигнеев Никита Артёмович<br/>Группа P3431<br/><br/>Практик: Рыбаков Степан Дмитриевич', 'right'), Spacer(1, 28 * mm), p('2026', 'center'), PageBreak()]
    story += [p('1. Уязвимость и контролируемый стенд', 'head'),
        p('Цель: воспроизвести известную уязвимость, объяснить причину и проверить устранение без нарушения обычной работы сервиса.'),
        p('<b>CVE-2021-43798:</b> обход каталога (directory traversal, CWE-22) в Grafana версий 8.0.0-beta1 - 8.3.0. Обработчик статических файлов плагина позволяет неаутентифицированному пользователю выйти за пределы каталога плагина и прочитать произвольные файлы, доступные процессу Grafana, по пути вида /public/plugins/&lt;id_плагина&gt;/&lt;обход&gt;. Исправлено в 8.3.1.'),
        p(f'<b>CVSS 3.1: {cvss["baseScore"]} {cvss["baseSeverity"]}</b> (источник {metric["source"]}, тип {metric["type"]}).', 'small'),
        Preformatted(cvss['vectorString'], S['code']),
        p('Вектор C:H/I:N/A:N отражает высокое влияние на конфиденциальность (чтение произвольных файлов) без прямого влияния на целостность и доступность. Атака не требует аутентификации и взаимодействия пользователя. Источник сохранён в evidence/nvd-CVE-2021-43798.json.', 'small'),
        table([['Контейнер', 'Версия / адрес', 'Назначение'], ['vulnerable', f'Grafana {vuln["version"]}\n127.0.0.1:{vuln["port"]}', 'Воспроизведение исходной ошибки'], ['fixed', f'Grafana {fixed["version"]}\n127.0.0.1:{fixed["port"]}', 'Контроль исправленной версии']], [.20, .36, .44]),
        Spacer(1, 8),
        p('Использованы официальные образы grafana/grafana. В оба контейнера только для чтения смонтирован специально подготовленный учебный файл /tmp/lab2-proof.txt без персональных данных; именно он читается при проверке вместо конфигов и паролей. Контейнеры опубликованы только на loopback 127.0.0.1; проверка не обращается к внешним адресам и не читает файлы хоста.'),
        p('Причина в исходном коде', 'sub'),
        p('Маршрут отдачи ресурсов плагина брал имя файла из URL и соединял его с каталогом плагина без очистки и нормализации сегментов «../». Выход за пределы базового каталога не проверялся, поэтому последовательности «../» уводили чтение вверх по файловой системе. В качестве точки входа используется штатный встроенный плагин alertlist; сторонние плагины не устанавливались.'),
        p('Это дефект кода обработки пути, доступный без аутентификации. Исправление в 8.3.1 добавляет очистку и проверку запрошенного пути, поэтому тот же запрос возвращает отказ.'),
        PageBreak()]
    story += [p('2. Воспроизведение и применение исправления', 'head'),
        p(f'Последняя фактическая проверка: {checked}. Запуск выполнен из корня проекта:'),
        Preformatted('docker compose -f lab2/compose.yaml up -d\npython3 lab2/demo.py', S['code']),
        p('demo.py вызывает verify.py. В нём зафиксированы два localhost-порта (18083 - уязвимый, 18084 - исправленный); он отправляет одинаковые запросы в оба контейнера, проверяет версию через /api/health, код ответа и содержимое, затем сохраняет results.json.'),
        p('Запрос из выполненной проверки', 'sub'),
        Preformatted('GET ' + attack_path, S['code']),
        p('Клиент http.client сохраняет заданный путь без нормализации на стороне клиента. При демонстрации через curl нужен --path-as-is, иначе «../» могут быть свёрнуты до отправки. Путь обращается только к подготовленному файлу /tmp/lab2-proof.txt.'),
        figure('04-recheck-terminal.png', 'Рисунок 1. Вывод verify.py: все шесть проверок пройдены.', 96),
        p('Применённое изменение', 'sub'),
        p('Исправление - обновление базового образа Grafana с уязвимого 8.3.0 на 8.3.1 (официальный патч безопасности). Сравнение выполняется двумя отдельными сервисами Compose, поэтому один и тот же запрос можно повторить рядом. Прочие условия одинаковы в обоих контейнерах, поэтому различие вызвано именно версией.'),
        p('Для современного развёртывания нужны актуальная поддерживаемая версия Grafana, запуск от непривилегированного пользователя и ограничение доступных процессу файлов.'),
        PageBreak()]
    story += [p('3. Верификация и выводы', 'head'),
        figure('05-http-comparison-terminal.png', 'Рисунок 2. Сравнение HTTP-ответов: уязвимая версия читает файл по обходу каталога, исправленная отклоняет тот же запрос.', 92)]
    rows = [['Проверка', f'Grafana {vuln["version"]}', f'Grafana {fixed["version"]}']]
    rows.append(['Версия (/api/health)', vuln['version'], fixed['version']])
    rows.append(['Обход каталога → файл', f'HTTP {vuln["traversal"]["status"]}; маркер файла получен', f'HTTP {fixed["traversal"]["status"]}; содержимого файла нет'])
    rows.append(['Несуществующий файл', f'HTTP {vuln["missing"]["status"]}; не раскрыт', f'HTTP {fixed["missing"]["status"]}; не раскрыт'])
    rows.append(['Обычный вход /login', f'HTTP {vuln["login"]["status"]}; работает', f'HTTP {fixed["login"]["status"]}; работает'])
    story += [table(rows, [.34, .33, .33]), Spacer(1, 7),
        p('Полученный маркер подтверждает чтение файла за пределами каталога плагина. В исправленной версии тот же запрос возвращает отказ и не выдаёт содержимого; обычный вход /login в обеих версиях отвечает 200 - это регрессионная проверка, что исправление не сломало штатную работу. Читался только подготовленный файл; конфигурация и пароли Grafana не запрашивались.', 'small'),
        p('Контрольные вопросы', 'sub'),
        p('<b>Зачем Docker?</b> Он даёт воспроизводимое изолированное окружение и позволяет удалить учебный сервис, не ставя уязвимую версию на хост. Изоляция не абсолютна: здесь дополнительно ограничена публикация портов только на loopback.', 'small'),
        p('<b>Уязвимость и эксплойт:</b> уязвимость - дефект обработки пути ресурсов плагина; эксплойт - конкретный запрос с «../», использующий этот дефект для чтения файла.', 'small'),
        p('<b>Зачем регрессионная проверка?</b> Запретить всё можно и отключением сервиса. Ответ 200 на /login подтверждает, что после обновления штатная работа сохранилась.', 'small'),
        p('<b>Зачем специалисту воспроизводить CVE?</b> Чтобы проверить условия эксплуатации, обоснованно оценить последствия, распознать признаки в журналах и подтвердить исправление.', 'small'),
        p('Вывод: все шесть проверок успешны. В исправленной версии именно проверенные запросы больше не срабатывают; полный аудит всех уязвимостей версии не проводился.', 'small'),
        p('Источники', 'sub'),
        p('<link href="https://nvd.nist.gov/vuln/detail/CVE-2021-43798">NVD: CVE-2021-43798</link>; <link href="https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/">Grafana Security Release 8.3.1</link>; <link href="https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p">GHSA-8pjx-jj86-j47p</link>; <link href="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-43798">NVD API (CVSS)</link>.', 'small')]
    output = ROOT / 'output/pdf/Евстигнеев Н.А. P3431 Работа 2.pdf'
    output.parent.mkdir(parents=True, exist_ok=True)
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('TimesRU', 9)
        canvas.setFillColor(colors.HexColor('#555555'))
        canvas.drawString(25 * mm, 12 * mm, 'Изолированный учебный стенд, только localhost')
        canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, str(doc.page))
        canvas.restoreState()
    SimpleDocTemplate(str(output), pagesize=A4, leftMargin=25 * mm, rightMargin=20 * mm, topMargin=20 * mm, bottomMargin=20 * mm, title='Работа 2. CVE-2021-43798: повторная проверка', author='Евстигнеев Никита Артёмович').build(story, onFirstPage=footer, onLaterPages=footer)
    print(output)


if __name__ == '__main__':
    main()
