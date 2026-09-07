"""OPNsense firewall dashboard generator (Lens-only, Kibana 9.5).

Firewall data has a different shape from alert data, so this deliberately does
not reuse the alert-overview layout:

  - a port x time heatmap, which is where a port sweep becomes visible as a
    horizontal band and a service scan as a vertical one
  - TCP flag distribution, which separates an ordinary SYN connection attempt
    from FIN, NULL and Xmas scans
  - interface x action and protocol x direction as nested donuts, standing in
    for a flow diagram, which Lens has no mark for
  - rule hit ranking, since "which rule is dropping this" is the question a
    firewall operator actually asks
  - blocked and passed traffic side by side rather than blocked alone
"""
import json, uuid, sys

DV = "opnsense-log-dv"
DATASET = "opnsense.log"

PALETTE = {"name": "default", "type": "palette"}
HEAT_PALETTE = {"name": "warm", "type": "palette"}
KPI_TINT = {"blue": "#BCD6F0", "red": "#F7C3B1", "purple": "#CFBEE9", "teal": "#B4E0CF"}

# Action colours carry meaning here, unlike a categorical series: block is the
# thing you look for, pass is context.
C_BLOCK, C_PASS = "#E7664C", "#54B399"

L = {
    "dash_title": "[Logs OPNsense] Firewall Activity",
    "dash_desc": "Packet filter decisions from OPNsense, collected by the opnsense integration.",
    "search_title": "[Logs OPNsense] Recent firewall events",
}


def rid(): return str(uuid.uuid4())


# ---------------------------------------------------------------- columns
def c_count(label, kql=None):
    c = {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
         "operationType": "count", "params": {"emptyAsNull": False}, "scale": "ratio",
         "sourceField": "___records___"}
    if kql:
        c["filter"] = {"query": kql, "language": "kuery"}
    return c


def c_unique(field, label):
    return {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
            "operationType": "unique_count", "params": {"emptyAsNull": False}, "scale": "ratio",
            "sourceField": field}


def c_max_date(label):
    return {"customLabel": True, "dataType": "date", "isBucketed": False, "label": label,
            "operationType": "max", "params": {"emptyAsNull": False}, "scale": "ratio",
            "sourceField": "@timestamp"}


def c_last(field, label):
    return {"customLabel": True, "dataType": "string", "isBucketed": False, "label": label,
            "operationType": "last_value", "params": {"sortField": "@timestamp", "showArrayValues": False},
            "scale": "ordinal", "sourceField": field}


def c_terms(field, label, order_col, size=10):
    return {"customLabel": True, "dataType": "string", "isBucketed": True, "label": label,
            "operationType": "terms",
            "params": {"exclude": [], "excludeIsRegex": False, "include": [], "includeIsRegex": False,
                       "missingBucket": False, "orderBy": {"columnId": order_col, "type": "column"},
                       "orderDirection": "desc", "otherBucket": True, "parentFormat": {"id": "terms"},
                       "size": size},
            "scale": "ordinal", "sourceField": field}


def c_date(interval="auto"):
    return {"customLabel": True, "dataType": "date", "isBucketed": True, "label": "@timestamp",
            "operationType": "date_histogram",
            "params": {"dropPartials": False, "includeEmptyRows": True, "interval": interval},
            "scale": "interval", "sourceField": "@timestamp"}


def c_formula_ratio(label, num_kql):
    main = rid()
    x0, x1, x2 = main + "X0", main + "X1", main + "X2"
    formula = f"count(kql='{num_kql}') / count()"
    return main, {
        main: {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
               "operationType": "formula",
               "params": {"formula": formula, "isFormulaBroken": False,
                          "format": {"id": "percent", "params": {"decimals": 1}}},
               "references": [x2], "scale": "ratio"},
        x0: {"customLabel": True, "dataType": "number", "isBucketed": False, "label": "Part of " + label,
             "operationType": "count", "params": {"emptyAsNull": False}, "scale": "ratio",
             "sourceField": "___records___", "filter": {"query": num_kql, "language": "kuery"}},
        x1: {"customLabel": True, "dataType": "number", "isBucketed": False, "label": "Part of " + label,
             "operationType": "count", "params": {"emptyAsNull": False}, "scale": "ratio",
             "sourceField": "___records___"},
        x2: {"customLabel": True, "dataType": "number", "isBucketed": False, "label": "Part of " + label,
             "operationType": "math",
             "params": {"tinymathAst": {"type": "function", "name": "divide", "args": [x0, x1],
                                        "location": {"min": 0, "max": len(formula)}, "text": formula}},
             "references": [x0, x1], "scale": "ratio"},
    }, [main, x0, x1, x2]


# ---------------------------------------------------------------- lens wrapper
def lens(vtype, title, layers, visualization):
    ds = {lid: {"columnOrder": order, "columns": cols, "incompleteColumns": {}}
          for lid, (cols, order) in layers.items()}
    return {
        "references": [{"id": DV, "name": f"indexpattern-datasource-layer-{lid}", "type": "index-pattern"}
                       for lid in layers],
        "state": {
            "adHocDataViews": {},
            # Kibana's 7.13.1 Lens migration reads datasourceStates.indexpattern.layers
            # (the legacy key) on every by-value panel; without it the install fails.
            "datasourceStates": {"formBased": {"layers": ds},
                                 "indexpattern": {"layers": ds},
                                 "textBased": {"layers": {}}},
            "filters": [], "internalReferences": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": visualization,
        },
        "title": title, "type": "lens", "visualizationType": vtype,
    }


# ---------------------------------------------------------------- KPI
def kpi_count(label, kql=None):
    def f():
        m = rid(); return {m: c_count(label, kql)}, [m], m
    return f


def kpi_unique(field, label):
    def f():
        m = rid(); return {m: c_unique(field, label)}, [m], m
    return f


def kpi_formula(num_kql, label):
    def f():
        main, cols, order = c_formula_ratio(label, num_kql)
        return cols, order, main
    return f


def metric_panel(title, kpi_fn, tint):
    lid, tlid, tt = rid(), rid(), rid()
    cols, order, main = kpi_fn()
    tcols, torder, tmain = kpi_fn()
    tcols[tt] = c_date()
    vis = {"layerId": lid, "layerType": "data", "metricAccessor": main, "color": tint,
           "titlePosition": "bottom", "textAlign": "left", "size": "m", "showBar": False,
           "trendlineLayerId": tlid, "trendlineLayerType": "metricTrendline",
           "trendlineMetricAccessor": tmain, "trendlineTimeAccessor": tt}
    return lens("lnsMetric", title, {lid: (cols, order), tlid: (tcols, [tt] + torder)}, vis)


# ---------------------------------------------------------------- XY
XY_COMMON = {
    "legend": {"isVisible": True, "position": "right", "legendSize": "auto", "maxLines": 1,
               "shouldTruncate": True, "showSingleSeries": True},
    "valueLabels": "hide", "fittingFunction": "None",
    "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": True},
    "gridlinesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
}


def action_over_time(title):
    """Blocked and passed as two explicitly coloured series, not a terms split."""
    lid, t, b, p = rid(), rid(), rid(), rid()
    cols = {t: c_date(),
            b: c_count("Blocked", "event.action : block"),
            p: c_count("Passed", "event.action : pass")}
    vis = dict(XY_COMMON, preferredSeriesType="bar_stacked",
               layers=[{"layerId": lid, "layerType": "data", "accessors": [b, p],
                        "seriesType": "bar_stacked", "xAccessor": t,
                        "yConfig": [{"forAccessor": b, "color": C_BLOCK, "axisMode": "left"},
                                    {"forAccessor": p, "color": C_PASS, "axisMode": "left"}],
                        "palette": PALETTE}])
    return lens("lnsXY", title, {lid: (cols, [t, b, p])}, vis)


def trend_split(title, field, series="area_stacked", size=6):
    lid, t, s, m = rid(), rid(), rid(), rid()
    cols = {t: c_date(), s: c_terms(field, field, m, size), m: c_count("Events")}
    vis = dict(XY_COMMON, preferredSeriesType=series,
               layers=[{"layerId": lid, "layerType": "data", "accessors": [m],
                        "seriesType": series, "xAccessor": t, "splitAccessor": s,
                        "palette": PALETTE}])
    return lens("lnsXY", title, {lid: (cols, [t, s, m])}, vis)


# ---------------------------------------------------------------- heatmap
def heatmap_panel(title, y_field, y_label, y_size=15, kql=None):
    """Time on x, a term on y, count as colour.

    A port sweep from one source shows up as a vertical stripe; a sustained
    attack on one service shows up as a horizontal band.
    """
    lid, t, y, m = rid(), rid(), rid(), rid()
    cols = {t: c_date(), y: c_terms(y_field, y_label, m, y_size), m: c_count("Events", kql)}
    vis = {"shape": "heatmap", "layerId": lid, "layerType": "data",
           "legend": {"isVisible": True, "position": "right", "type": "heatmap_legend"},
           "gridConfig": {"type": "heatmap_grid", "isCellLabelVisible": False,
                          "isYAxisLabelVisible": True, "isXAxisLabelVisible": True,
                          "isYAxisTitleVisible": False, "isXAxisTitleVisible": False},
           "valueAccessor": m, "xAccessor": t, "yAccessor": y,
           "palette": {"name": "warm", "type": "palette",
                       "params": {"name": "warm", "reverse": False, "rangeType": "percent",
                                  "rangeMin": 0, "rangeMax": None, "progression": "fixed",
                                  "stops": [], "colorStops": [], "continuity": "above",
                                  "maxSteps": 5}}}
    return lens("lnsHeatmap", title, {lid: (cols, [t, y, m])}, vis)


# ---------------------------------------------------------------- partition
def partition_panel(title, field, label, shape="donut", size=8, second=None, second_label=None):
    """A donut, and with a second field a nested donut.

    Both dimensions still read at a glance as concentric rings. A mosaic or
    waffle renders the same data as a grid of near-identical squares, which is
    unreadable once two categories share a colour ramp.
    """
    lid, b, m = rid(), rid(), rid()
    cols = {b: c_terms(field, label, m, size), m: c_count("Events")}
    order = [b, m]
    groups = [b]
    if second:
        b2 = rid()
        cols[b2] = c_terms(second, second_label, m, 4)
        order = [b, b2, m]
        groups = [b, b2]
    layer = {"layerId": lid, "layerType": "data", "primaryGroups": groups, "metrics": [m],
             "numberDisplay": "percent", "categoryDisplay": "default",
             "legendDisplay": "show", "nestedLegend": bool(second), "truncateLegend": True}
    vis = {"shape": shape, "palette": PALETTE, "layers": [layer]}
    return lens("lnsPie", title, {lid: (cols, order)}, vis)


# ---------------------------------------------------------------- table
def table_panel(title, bucket_field, bucket_label, metrics, size=10):
    lid, b = rid(), rid()
    mids = [rid() for _ in metrics]
    cols = {b: c_terms(bucket_field, bucket_label, mids[0], size)}
    for mid, mc in zip(mids, metrics):
        cols[mid] = mc
    order = [b] + mids
    vis = {"layerId": lid, "layerType": "data",
           "columns": [{"columnId": c, "alignment": "left"} for c in order],
           "paging": {"enabled": True, "size": 10}, "headerRowHeight": "single", "rowHeight": "single"}
    return lens("lnsDatatable", title, {lid: (cols, order)}, vis)


# ---------------------------------------------------------------- map
def map_attrs(title):
    grid_id = rid()
    layers = [
        {"locale": "autoselect",
         "sourceDescriptor": {"type": "EMS_TMS", "isAutoSelect": True,
                              "lightModeDefault": "road_map_desaturated"},
         "id": rid(), "label": None, "minZoom": 0, "maxZoom": 24, "alpha": 1, "visible": True,
         "style": {"type": "EMS_VECTOR_TILE", "color": ""}, "includeInFitToBounds": True,
         "type": "EMS_VECTOR_TILE"},
        {"sourceDescriptor": {"geoField": "source.geo.location", "requestType": "heatmap",
                              "resolution": "SUPER_FINE", "id": grid_id, "type": "ES_GEO_GRID",
                              "applyGlobalQuery": True, "applyGlobalTime": True,
                              "applyForceRefresh": True, "metrics": [{"type": "count"}],
                              "indexPatternRefName": "layer_1_source_index_pattern"},
         "id": rid(), "label": None, "minZoom": 0, "maxZoom": 24, "alpha": 0.75, "visible": True,
         "style": {"type": "HEATMAP", "colorRampName": "theclassic"},
         "includeInFitToBounds": True, "type": "HEATMAP"},
    ]
    state = {"adHocDataViews": [], "zoom": 1.6, "center": {"lon": 10, "lat": 30},
             "timeFilters": {"from": "now-24h", "to": "now"},
             "refreshConfig": {"isPaused": True, "interval": 60000},
             "query": {"query": "", "language": "kuery"},
             "filters": [{"meta": {"disabled": False, "negate": False, "alias": None, "index": DV,
                                   "key": "data_stream.dataset", "field": "data_stream.dataset",
                                   "params": {"query": DATASET}, "type": "phrase"},
                          "query": {"match_phrase": {"data_stream.dataset": DATASET}},
                          "$state": {"store": "appState"}}],
             "settings": {"autoFitToDataBounds": True, "customIcons": [],
                          "disableInteractive": False, "disableTooltipControl": False,
                          "hideToolbarOverlay": False, "hideLayerControl": False,
                          "hideViewControl": False, "initialLocation": "AUTO_FIT_TO_BOUNDS",
                          "fixedLocation": {"lat": 0, "lon": 0, "zoom": 2},
                          "browserLocation": {"zoom": 2}, "keydownScrollZoom": False,
                          "maxZoom": 24, "minZoom": 0,
                          "showScaleControl": False, "showSpatialFilters": True,
                          "showTimesliderToggleButton": True,
                          "spatialFiltersAlpa": 0.3, "spatialFiltersFillColor": "#DA8B45",
                          "spatialFiltersLineColor": "#DA8B45"}}
    return {"description": "", "layerListJSON": json.dumps(layers), "mapStateJSON": json.dumps(state),
            "title": title, "uiStateJSON": json.dumps({"isLayerTOCOpen": False, "openTOCDetails": []})}


# ---------------------------------------------------------------- saved search
SEARCH_COLUMNS = ["event.action", "opnsense.log.interface", "network.direction",
                  "network.transport", "source.ip", "source.port", "destination.ip",
                  "destination.port", "opnsense.log.tcp.flags", "rule.id"]


def search_object(sid, title):
    ss = {"filter": [{"$state": {"store": "appState"},
                      "meta": {"alias": None, "disabled": False, "field": "data_stream.dataset",
                               "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index",
                               "key": "data_stream.dataset", "negate": False, "params": {"query": DATASET},
                               "type": "phrase"},
                      "query": {"match_phrase": {"data_stream.dataset": DATASET}}}],
          "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
          "query": {"language": "kuery", "query": ""}}
    return {"id": sid, "type": "search", "coreMigrationVersion": "8.8.0",
            "typeMigrationVersion": "8.0.0",
            "attributes": {"title": title, "description": "", "columns": SEARCH_COLUMNS,
                           "sort": [["@timestamp", "desc"]], "grid": {}, "hideChart": True,
                           "isTextBasedQuery": False, "usesAdHocDataView": False, "timeRestore": False,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)}},
            "references": [{"id": DV, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"},
                           {"id": DV, "name": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index",
                            "type": "index-pattern"}]}


# ---------------------------------------------------------------- dashboard
def build():
    dash_id, search_id = "opnsense-firewall-activity", "opnsense-recent-events"

    layout = [
        # row 1 — KPIs
        ("lens", metric_panel("Events", kpi_count("events"), KPI_TINT["blue"]), 0, 0, 12, 6),
        ("lens", metric_panel("Block rate", kpi_formula("event.action : block", "blocked"), KPI_TINT["red"]), 12, 0, 12, 6),
        ("lens", metric_panel("Unique sources", kpi_unique("source.ip", "source IPs"), KPI_TINT["purple"]), 24, 0, 12, 6),
        ("lens", metric_panel("Ports targeted", kpi_unique("destination.port", "ports"), KPI_TINT["teal"]), 36, 0, 12, 6),
        # row 2 — blocked vs passed, and per interface
        ("lens", action_over_time("Blocked and passed over time"), 0, 6, 24, 13),
        ("lens", trend_split("Traffic over time by interface", "opnsense.log.interface"), 24, 6, 24, 13),
        # row 3 — the scan-detection row
        ("lens", heatmap_panel("Targeted ports over time (blocked)", "destination.port", "Port",
                               y_size=15, kql="event.action : block"), 0, 19, 32, 16),
        ("lens", partition_panel("TCP flags", "opnsense.log.tcp.flags", "Flags", shape="donut", size=8),
         32, 19, 16, 16),
        # row 4 — flow-shaped views
        ("lens", partition_panel("Interface by action", "opnsense.log.interface", "Interface",
                                 shape="donut", size=6, second="event.action", second_label="Action"),
         0, 35, 24, 15),
        ("lens", partition_panel("Protocol by direction", "network.transport", "Protocol",
                                 shape="donut", size=6, second="network.direction", second_label="Direction"),
         24, 35, 24, 15),
        # row 5 — what a firewall operator actually asks
        ("lens", table_panel("Rules firing most", "rule.id", "Rule",
                             [c_count("Events"), c_last("event.action", "Action"),
                              c_unique("source.ip", "Sources"), c_max_date("Last seen")], size=12),
         0, 50, 24, 15),
        ("lens", table_panel("Top sources", "source.ip", "Source IP",
                             [c_count("Events"), c_count("Blocked", "event.action : block"),
                              c_unique("destination.port", "Ports"),
                              c_last("source.geo.country_iso_code", "Country")], size=12),
         24, 50, 24, 15),
        # row 6 — geography and targets
        ("map", map_attrs("Source locations"), 0, 65, 28, 16),
        ("lens", table_panel("Most targeted ports", "destination.port", "Port",
                             [c_count("Events"), c_unique("source.ip", "Sources")], size=12),
         28, 65, 20, 16),
        # row 7 — detail
        ("search", None, 0, 81, 48, 18),
    ]

    panels, refs = [], []
    for i, (ptype, att, x, y, w, h) in enumerate(layout):
        pidx = str(i + 1)
        grid = {"x": x, "y": y, "w": w, "h": h, "i": pidx}
        if ptype == "lens":
            for r in att["references"]:
                refs.append({"id": r["id"], "name": f"{pidx}:{r['name']}", "type": r["type"]})
            panels.append({"type": "lens", "gridData": grid, "panelIndex": pidx, "title": att["title"],
                           "embeddableConfig": {"attributes": att, "enhancements": {}, "hidePanelTitles": False},
                           "version": "8.10.1"})
        elif ptype == "map":
            refs.append({"id": DV, "name": f"{pidx}:layer_1_source_index_pattern", "type": "index-pattern"})
            # The map is walked by the same by-value Lens migration, so it needs a
            # minimal datasource state to pass through it safely.
            att.setdefault("state", {"datasourceStates": {"formBased": {"layers": {}},
                                                          "indexpattern": {"layers": {}},
                                                          "textBased": {"layers": {}}}})
            panels.append({"type": "map", "gridData": grid, "panelIndex": pidx, "title": att["title"],
                           "embeddableConfig": {"attributes": att, "enhancements": {}, "hidePanelTitles": False,
                                                "mapCenter": {"lat": 30, "lon": 10, "zoom": 1.6},
                                                "isLayerTOCOpen": False, "openTOCDetails": [],
                                                "hiddenLayers": []},
                           "version": "8.10.1"})
        else:
            refs.append({"id": search_id, "name": f"{pidx}:panel_{pidx}", "type": "search"})
            panels.append({"type": "search", "gridData": grid, "panelIndex": pidx,
                           "panelRefName": f"panel_{pidx}", "title": L["search_title"],
                           "embeddableConfig": {"enhancements": {}}, "version": "8.10.1"})

    controls = [("event.action", "Action"), ("opnsense.log.interface", "Interface"),
                ("network.transport", "Protocol"), ("network.direction", "Direction")]
    cpanels = {}
    for order, (field, title) in enumerate(controls):
        cid = rid()
        cpanels[cid] = {"type": "optionsListControl", "order": order, "grow": True, "width": "medium",
                        "explicitInput": {"id": cid, "fieldName": field, "title": title, "grow": True,
                                          "width": "medium", "enhancements": {}}}
        refs.append({"id": DV, "name": f"controlGroup_{cid}:optionsListDataView", "type": "index-pattern"})
    control_group = {"chainingSystem": "HIERARCHICAL", "controlStyle": "oneLine",
                     "ignoreParentSettingsJSON": json.dumps({"ignoreFilters": False, "ignoreQuery": False,
                                                             "ignoreTimerange": False, "ignoreValidations": False}),
                     "panelsJSON": json.dumps(cpanels)}

    refs.append({"id": DV, "name": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index",
                 "type": "index-pattern"})
    ss = {"query": {"query": "", "language": "kuery"},
          "filter": [{"$state": {"store": "appState"},
                      "meta": {"alias": None, "disabled": False, "negate": False, "type": "phrase",
                               "key": "data_stream.dataset", "params": {"query": DATASET},
                               "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index"},
                      "query": {"match_phrase": {"data_stream.dataset": DATASET}}}]}

    # Without typeMigrationVersion Kibana replays the whole migration chain and
    # rewrites panel types, empties partition metrics and drops search columns.
    dash = {"id": dash_id, "type": "dashboard", "coreMigrationVersion": "8.8.0",
            "typeMigrationVersion": "8.9.0",
            "attributes": {"title": L["dash_title"], "description": L["dash_desc"],
                           "panelsJSON": json.dumps(panels, ensure_ascii=False),
                           "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False,
                                                      "syncColors": True, "syncCursor": True,
                                                      "syncTooltips": False}),
                           "controlGroupInput": control_group,
                           "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)}},
            "references": refs}
    return dash, search_object(search_id, L["search_title"])


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    dash, search = build()
    open(f"{out}/dash.json", "w").write(json.dumps(dash, ensure_ascii=False, indent=2) + "\n")
    open(f"{out}/search.json", "w").write(json.dumps(search, ensure_ascii=False, indent=2) + "\n")
    n = len(json.loads(dash["attributes"]["panelsJSON"]))
    print(f"dashboard {dash['id']} panels={n} refs={len(dash['references'])}; search {search['id']}")
