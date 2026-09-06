"""CrowdSec alerts overview dashboard generator (Lens-only, Kibana 9.5) — v2 style.

Produces:
  - a dashboard saved object with by-value Lens panels, a by-value Map panel,
    a by-reference saved search panel, and an options-list control group
  - the saved search object the dashboard references

Design decisions:
  - KPI tiles carry a sparkline trendline layer instead of being flat numbers
  - one categorical palette everywhere + syncColors, so a scenario is the same
    colour in every panel
  - scenario x country heat matrix (transposed datatable) replaces a third top-N list
  - treemap instead of a donut (7+ categories read badly in a donut)
  - no hardcoded white map background, so dark mode is not broken
  - extra panels: AS/hosting orgs, attack tools, alert intensity per scenario

Structures mirror the official cloudflare / imperva_cloud_waf packages.
"""
import json, uuid, sys

DV = "crowdsec-alert-dv"   # single data view; field labels stay English
DATASET = "crowdsec.alert"

# One categorical palette for every panel. Combined with syncColors on the
# dashboard this keeps a given scenario the same colour across panels.
# "default" is Elastic's current categorical ramp (Borealis on 9.x); the older
# "kibana_palette" is the legacy rainbow and its neighbouring hues clash badly
# once a chart carries six or seven series.
PALETTE = {"name": "default", "type": "palette"}
# Counts are sequential, not categorical, so the heat matrix gets a one-directional
# ramp. "temperature" is diverging (blue<->red) and implies a midpoint that a
# count has no meaning for.
HEAT_PALETTE = {"name": "warm", "type": "palette"}
# Lens only exposes one colour knob on a metric and it fills the whole tile, so
# these have to stay light enough for dark value text and the sparkline drawn
# over them - but not so pale they read as plain white.
KPI_TINT = {"blue": "#BCD6F0", "green": "#B4E0CF", "red": "#F7C3B1", "purple": "#CFBEE9"}

L = {
  "en": {
    "dash_title": "[Logs CrowdSec] Alerts Overview",
    "dash_desc": "Alerts and remediation decisions from CrowdSec, collected by the crowdsec integration.",
    "search_title": "[Logs CrowdSec] Recent alerts",
    "c_scenario": "Scenario", "c_author": "Rule author", "c_decision": "Decision", "c_country": "Country",
    "k_total": "Alerts", "k_total_l": "alerts",
    "k_rate": "Ban rate", "k_rate_l": "banned",
    "k_scen": "Distinct scenarios", "k_scen_l": "scenarios",
    "k_ips": "Unique sources", "k_ips_l": "source IPs",
    "t_scen": "Alerts over time by scenario", "t_country": "Alerts over time by source country",
    "map": "Alert sources", "pie_scen": "Scenario breakdown",
    "heat": "Scenario x country",
    "tbl_ip": "Repeat offenders", "tbl_scen": "Top scenarios", "tbl_path": "Top target paths",
    "tbl_as": "Top networks (AS)", "tbl_ua": "Attack tools", "tbl_int": "Alert intensity by scenario",
    "col_ip": "Source IP", "col_count": "Alerts", "col_scens": "Scenarios",
    "col_last": "Last seen", "col_country": "Country",
    "col_scen": "Scenario", "col_path": "Path", "col_as": "Network",
    "col_ua": "User agent", "col_events": "Events",
    "col_avg": "Avg events/alert", "col_max": "Peak events",
  },
}


def rid(): return str(uuid.uuid4())


# ---------------------------------------------------------------- columns
def c_count(label, kql=None):
    c = {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
         "operationType": "count", "params": {"emptyAsNull": False}, "scale": "ratio",
         "sourceField": "___records___"}
    if kql: c["filter"] = {"query": kql, "language": "kuery"}
    return c


def c_unique(field, label):
    return {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
            "operationType": "unique_count", "params": {"emptyAsNull": False}, "scale": "ratio",
            "sourceField": field}


def c_sum(field, label):
    return {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
            "operationType": "sum", "params": {"emptyAsNull": False}, "scale": "ratio",
            "sourceField": field}


def c_avg(field, label):
    return {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
            "operationType": "average", "params": {"emptyAsNull": False,
                                                   "format": {"id": "number", "params": {"decimals": 1}}},
            "scale": "ratio", "sourceField": field}


def c_max(field, label):
    return {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
            "operationType": "max", "params": {"emptyAsNull": False}, "scale": "ratio",
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


def c_date():
    return {"customLabel": True, "dataType": "date", "isBucketed": True, "label": "@timestamp",
            "operationType": "date_histogram",
            "params": {"dropPartials": False, "includeEmptyRows": True, "interval": "auto"},
            "scale": "interval", "sourceField": "@timestamp"}


def c_formula_ratio(label, num_kql):
    """count(kql=...) / count(), rendered as a percent. Returns (main_id, columns, order)."""
    main = rid()
    x0, x1, x2 = main + "X0", main + "X1", main + "X2"
    formula = f"count(kql='{num_kql}') / count()"
    cols = {
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
    }
    return main, cols, [main, x0, x1, x2]


# ---------------------------------------------------------------- lens wrapper
def lens(vtype, title, layers, visualization):
    """layers: {layer_id: (columns_dict, column_order_list)}"""
    ds = {lid: {"columnOrder": order, "columns": cols, "incompleteColumns": {}}
          for lid, (cols, order) in layers.items()}
    return {
        "references": [{"id": DV, "name": f"indexpattern-datasource-layer-{lid}", "type": "index-pattern"}
                       for lid in layers],
        "state": {
            "adHocDataViews": {},
            # Kibana's 7.13.1 Lens migration reads datasourceStates.indexpattern.layers
            # (the legacy key) on every by-value panel. Without it the install fails with
            # "Cannot read properties of undefined (reading 'layers')".
            "datasourceStates": {"formBased": {"layers": ds},
                                 "indexpattern": {"layers": ds},
                                 "textBased": {"layers": {}}},
            "filters": [], "internalReferences": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": visualization,
        },
        "title": title, "type": "lens", "visualizationType": vtype,
    }


# ---------------------------------------------------------------- KPI tiles
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
        # an empty label makes Lens fall back to printing "Formula" in the tile
        main, cols, order = c_formula_ratio(label, num_kql)
        return cols, order, main
    return f


def metric_panel(title, kpi_fn, tint=None):
    """A metric tile with a sparkline trendline layer underneath the number.

    The trendline needs its own datasource layer holding the same metric plus a
    date histogram, so the KPI factory is instantiated twice with fresh column ids.
    """
    lid, tlid, tt = rid(), rid(), rid()
    cols, order, main = kpi_fn()
    tcols, torder, tmain = kpi_fn()
    tcols[tt] = c_date()
    # `color` fills the whole tile, so only pale tints are usable here: a
    # saturated value buries the sparkline and swamps the first screen.
    vis = {"layerId": lid, "layerType": "data", "metricAccessor": main,
           "titlePosition": "bottom", "textAlign": "left", "size": "m",
           "showBar": False,
           "trendlineLayerId": tlid, "trendlineLayerType": "metricTrendline",
           "trendlineMetricAccessor": tmain, "trendlineTimeAccessor": tt}
    if tint: vis["color"] = tint
    return lens("lnsMetric", title, {lid: (cols, order), tlid: (tcols, [tt] + torder)}, vis)


# ---------------------------------------------------------------- XY
XY_COMMON = {
    "legend": {"isVisible": True, "position": "right", "legendSize": "auto", "maxLines": 1,
               "shouldTruncate": True, "showSingleSeries": True},
    "valueLabels": "hide", "fittingFunction": "None",
    "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": True},
    "gridlinesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
}


def trend_by_terms_panel(title, field, size=6):
    lid, t, s, m = rid(), rid(), rid(), rid()
    cols = {t: c_date(), s: c_terms(field, field, m, size), m: c_count("Count")}
    vis = dict(XY_COMMON, preferredSeriesType="bar_stacked",
               layers=[{"layerId": lid, "layerType": "data", "accessors": [m], "seriesType": "bar_stacked",
                        "xAccessor": t, "splitAccessor": s, "palette": PALETTE}])
    return lens("lnsXY", title, {lid: (cols, [t, s, m])}, vis)


# ---------------------------------------------------------------- partition
def partition_panel(title, field, label, shape="treemap", size=10):
    lid, b, m = rid(), rid(), rid()
    cols = {b: c_terms(field, label, m, size), m: c_count("Count")}
    # Keep exactly this key set. Extra keys — an empty secondaryGroups in particular —
    # make Lens resolve columns per group and fail with
    # "Provided column name or index is invalid".
    vis = {"shape": shape, "palette": PALETTE,
           "layers": [{"layerId": lid, "layerType": "data", "primaryGroups": [b],
                       "metrics": [m], "numberDisplay": "percent", "categoryDisplay": "default",
                       "legendDisplay": "show", "nestedLegend": False, "truncateLegend": True}]}
    return lens("lnsPie", title, {lid: (cols, [b, m])}, vis)


# ---------------------------------------------------------------- tables
def table_panel(title, bucket_field, bucket_label, metrics, size=10):
    """metrics: list of column dicts in display order; the first is the sort key."""
    lid, b = rid(), rid()
    mids = [rid() for _ in metrics]
    cols = {b: c_terms(bucket_field, bucket_label, mids[0], size)}
    for mid, mc in zip(mids, metrics): cols[mid] = mc
    order = [b] + mids
    vis = {"layerId": lid, "layerType": "data",
           "columns": [{"columnId": c, "alignment": "left"} for c in order],
           "paging": {"enabled": True, "size": 10}, "headerRowHeight": "single", "rowHeight": "single"}
    return lens("lnsDatatable", title, {lid: (cols, order)}, vis)


def heat_table_panel(title, row_field, row_label, col_field, col_label, rows=8, cols_n=8):
    """A transposed datatable: rows x columns matrix with colour-scaled cells.

    Denser than two separate top-N lists — it shows which scenario comes from
    which country, which neither list can.
    """
    lid, b1, b2, m = rid(), rid(), rid(), rid()
    columns = {
        b1: c_terms(row_field, row_label, m, rows),
        b2: c_terms(col_field, col_label, m, cols_n),
        m: c_count("Alerts"),
    }
    vis = {"layerId": lid, "layerType": "data",
           "columns": [{"columnId": b1, "alignment": "left"},
                       {"columnId": b2, "alignment": "center", "isTransposed": True},
                       {"columnId": m, "alignment": "center", "colorMode": "cell",
                        "palette": HEAT_PALETTE}],
           "paging": {"enabled": False, "size": 10},
           "headerRowHeight": "auto", "rowHeight": "single"}
    return lens("lnsDatatable", title, {lid: (columns, [b1, b2, m])}, vis)


# ---------------------------------------------------------------- map (by value)
def map_attrs(title):
    """EMS basemap + a count-weighted heatmap layer."""
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
             # backgroundColor is deliberately omitted; hardcoding #ffffff breaks dark mode
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
SEARCH_COLUMNS = ["source.ip", "source.geo.country_iso_code", "source.as.organization.name",
                  "crowdsec.scenario.author", "crowdsec.scenario.title", "crowdsec.decision.type",
                  "crowdsec.decision.duration", "crowdsec.events_count", "event.reason"]


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
def build(lang):
    R = L[lang]
    dash_id = "crowdsec-alerts-overview"
    search_id = "crowdsec-recent-alerts"

    layout = [
        # row 1: KPIs with sparklines
        ("lens", metric_panel(R["k_total"], kpi_count(R["k_total_l"]), KPI_TINT["blue"]), 0, 0, 12, 6),
        ("lens", metric_panel(R["k_rate"], kpi_formula("event.action : ban", R["k_rate_l"]), KPI_TINT["green"]), 12, 0, 12, 6),
        ("lens", metric_panel(R["k_scen"], kpi_unique("crowdsec.scenario.name", R["k_scen_l"]), KPI_TINT["red"]), 24, 0, 12, 6),
        ("lens", metric_panel(R["k_ips"], kpi_unique("source.ip", R["k_ips_l"]), KPI_TINT["purple"]), 36, 0, 12, 6),
        # row 2: trends
        ("lens", trend_by_terms_panel(R["t_scen"], "crowdsec.scenario.title"), 0, 6, 24, 13),
        ("lens", trend_by_terms_panel(R["t_country"], "source.geo.country_iso_code"), 24, 6, 24, 13),
        # row 3: map + scenario treemap
        ("map", map_attrs(R["map"]), 0, 19, 30, 16),
        ("lens", partition_panel(R["pie_scen"], "crowdsec.scenario.title", R["col_scen"]), 30, 19, 18, 16),
        # row 4: correlation matrix + repeat offenders
        ("lens", heat_table_panel(R["heat"], "crowdsec.scenario.title", R["col_scen"],
                                  "source.geo.country_iso_code", R["col_country"]), 0, 35, 24, 15),
        ("lens", table_panel(R["tbl_ip"], "source.ip", R["col_ip"],
                             [c_count(R["col_count"]), c_unique("crowdsec.scenario.name", R["col_scens"]),
                              c_sum("crowdsec.events_count", R["col_events"]),
                              c_max_date(R["col_last"]),
                              c_last("source.geo.country_iso_code", R["col_country"])]), 24, 35, 24, 15),
        # row 5: rankings
        ("lens", table_panel(R["tbl_scen"], "crowdsec.scenario.title", R["col_scen"],
                             [c_count(R["col_count"]), c_unique("source.ip", R["col_ip"])]), 0, 50, 16, 13),
        ("lens", table_panel(R["tbl_as"], "source.as.organization.name", R["col_as"],
                             [c_count(R["col_count"]), c_unique("source.ip", R["col_ip"])]), 16, 50, 16, 13),
        ("lens", table_panel(R["tbl_ua"], "user_agent.original", R["col_ua"],
                             [c_count(R["col_count"]), c_unique("source.ip", R["col_ip"])], size=8), 32, 50, 16, 13),
        # row 6: targets and remediation
        ("lens", table_panel(R["tbl_path"], "crowdsec.alert.paths", R["col_path"],
                             [c_count(R["col_count"])], size=15), 0, 63, 24, 14),
        ("lens", table_panel(R["tbl_int"], "crowdsec.scenario.title", R["col_scen"],
                             [c_count(R["col_count"]), c_avg("crowdsec.events_count", R["col_avg"]),
                              c_max("crowdsec.events_count", R["col_max"])], size=10), 24, 63, 24, 14),
        # row 7: detail
        ("search", None, 0, 77, 48, 18),
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
            # The map panel is walked by the same by-value Lens migration, so it needs a
            # minimal state to pass through it safely.
            att.setdefault("state", {"datasourceStates": {"formBased": {"layers": {}},
                                                          "indexpattern": {"layers": {}},
                                                          "textBased": {"layers": {}}}})
            panels.append({"type": "map", "gridData": grid, "panelIndex": pidx, "title": att["title"],
                           "embeddableConfig": {"attributes": att, "enhancements": {}, "hidePanelTitles": False,
                                                "mapCenter": {"lat": 30, "lon": 10, "zoom": 1.6},
                                                "isLayerTOCOpen": False, "openTOCDetails": [],
                                                "hiddenLayers": []},
                           "version": "8.10.1"})
        elif ptype == "search":
            refs.append({"id": search_id, "name": f"{pidx}:panel_{pidx}", "type": "search"})
            panels.append({"type": "search", "gridData": grid, "panelIndex": pidx, "panelRefName": f"panel_{pidx}",
                           "title": R["search_title"], "embeddableConfig": {"enhancements": {}}, "version": "8.10.1"})

    # control group
    controls = [("crowdsec.scenario.title", R["c_scenario"]), ("crowdsec.scenario.author", R["c_author"]),
                ("source.geo.country_iso_code", R["c_country"]), ("crowdsec.decision.type", R["c_decision"])]
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

    # dashboard-level dataset filter (SVR00002)
    refs.append({"id": DV, "name": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index", "type": "index-pattern"})
    ss = {"query": {"query": "", "language": "kuery"},
          "filter": [{"$state": {"store": "appState"},
                      "meta": {"alias": None, "disabled": False, "negate": False, "type": "phrase",
                               "key": "data_stream.dataset", "params": {"query": DATASET},
                               "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index"},
                      "query": {"match_phrase": {"data_stream.dataset": DATASET}}}]}

    # Without typeMigrationVersion Kibana runs the whole migration chain from the
    # earliest version: lnsMetric is rewritten to lnsLegacyMetric, pie metrics are
    # emptied, and the saved search loses its columns.
    dash = {"id": dash_id, "type": "dashboard", "coreMigrationVersion": "8.8.0",
            "typeMigrationVersion": "8.9.0",
            "attributes": {"title": R["dash_title"], "description": R["dash_desc"],
                           "panelsJSON": json.dumps(panels, ensure_ascii=False),
                           # syncColors keeps a scenario the same colour in every panel
                           "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False,
                                                      "syncColors": True, "syncCursor": True,
                                                      "syncTooltips": False}),
                           "controlGroupInput": control_group,
                           "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)}},
            "references": refs}
    return dash, search_object(search_id, R["search_title"])


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    for lang in ("en",):
        dash, search = build(lang)
        open(f"{out}/dash_{lang}.json", "w").write(json.dumps(dash, ensure_ascii=False, indent=2) + "\n")
        open(f"{out}/search_{lang}.json", "w").write(json.dumps(search, ensure_ascii=False, indent=2) + "\n")
        n = len(json.loads(dash["attributes"]["panelsJSON"]))
        print(f"{lang}: dashboard {dash['id']} panels={n} refs={len(dash['references'])}; search {search['id']}")
