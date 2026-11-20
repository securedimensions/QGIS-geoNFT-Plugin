"""Draw a deployment's observations on an OpenStreetMap base map."""

import json
import logging

from qgis.core import (
    QgsCategorizedSymbolRenderer,
    QgsCoordinateReferenceSystem,
    QgsCoordinateTransform,
    QgsFeature,
    QgsFeatureRequest,
    QgsJsonUtils,
    QgsMarkerSymbol,
    QgsProject,
    QgsRasterLayer,
    QgsRectangle,
    QgsRendererCategory,
    QgsVectorLayer,
    QgsWkbTypes,
)

from . import cs_api

_logger = logging.getLogger("geonft")

OSM_NAME = "OpenStreetMap"
OSM_HOST = "tile.openstreetmap.org"
OSM_URI = "type=xyz&url=https://tile.openstreetmap.org/%7Bz%7D/%7Bx%7D/%7By%7D.png&zmax=19&zmin=0"
GROUP_PREFIX = "Observations: "
# Set on every layer this plugin draws, so the inspect tool finds them.
# The cs_review/ prefix predates the geoNFT rebranding. It is stored in saved projects, so it stays.
LAYER_PROPERTY = "cs_review/observations"
# The deployment id of the layer, so a verification finds its observations.
DEPLOYMENT_PROPERTY = "cs_review/deployment"
CHAIN_FIELD = "chain_check"


OSM_ATTRIBUTION = "© OpenStreetMap contributors"
OSM_ATTRIBUTION_URL = "https://www.openstreetmap.org/copyright"


def _set_osm_attribution(layer):
    """Record the attribution the OSM tile usage policy asks for on the layer (Properties › Metadata/QGIS Server)."""
    try:
        metadata = layer.metadata()
        metadata.setRights([OSM_ATTRIBUTION + " (" + OSM_ATTRIBUTION_URL + ")"])
        metadata.setLicenses(["Open Database License (ODbL)"])
        layer.setMetadata(metadata)
    except Exception as err:  # older QGIS API: the attribution is optional metadata
        _logger.debug("OSM attribution not written to the layer metadata: %s", err)
    server = getattr(layer, "serverProperties", None)
    if server is not None:
        try:
            server().setAttribution(OSM_ATTRIBUTION)
            server().setAttributionUrl(OSM_ATTRIBUTION_URL)
        except Exception as err:
            _logger.debug("OSM attribution not written to the server properties: %s", err)


def ensure_osm_basemap(project=None):
    """Add the OSM tiles at the bottom of the layer tree unless the project has them."""
    project = project or QgsProject.instance()
    for layer in project.mapLayers().values():
        if OSM_HOST in (layer.source() or ""):
            return layer
    was_empty = not project.mapLayers()
    layer = QgsRasterLayer(OSM_URI, OSM_NAME, "wms")
    if not layer.isValid():
        raise RuntimeError("The OpenStreetMap base map could not be loaded.")
    _set_osm_attribution(layer)
    project.addMapLayer(layer, False)
    root = project.layerTreeRoot()
    root.insertLayer(len(root.children()), layer)
    if was_empty:
        project.setCrs(QgsCoordinateReferenceSystem("EPSG:3857"))
    return layer


def _replace_group(project, name):
    root = project.layerTreeRoot()
    old = root.findGroup(name)
    if old is not None:
        for layer_id in old.findLayerIds():
            project.removeMapLayer(layer_id)
        root.removeChildNode(old)
    return root.insertGroup(0, name)


def _telemetry_symbol():
    return QgsMarkerSymbol.createSimple({
        "name": "circle",
        "color": "230,57,70",
        "size": "2.6",
        "outline_color": "255,255,255",
        "outline_width": "0.4",
    })


def _image_symbol():
    return QgsMarkerSymbol.createSimple({
        "name": "square",
        "color": "29,111,214",
        "size": "4.4",
        "outline_color": "255,255,255",
        "outline_width": "0.6",
    })


def _style_points(layer):
    """Telemetry: small red circles. Images: larger blue squares, drawn on top.

    An image sits on the position observation it borrowed its location from,
    so images are drawn last to stay visible and clickable.
    """
    if layer.fields().indexOf("kind") < 0:
        renderer = layer.renderer()
        if renderer is not None and hasattr(renderer, "setSymbol"):
            renderer.setSymbol(_telemetry_symbol())
        return
    renderer = QgsCategorizedSymbolRenderer("kind", [
        QgsRendererCategory("telemetry", _telemetry_symbol(), "Telemetry"),
        QgsRendererCategory("image", _image_symbol(), "Image"),
    ])
    renderer.setOrderBy(QgsFeatureRequest.OrderBy([
        QgsFeatureRequest.OrderByClause("\"kind\" = 'image'", True),
    ]))
    renderer.setOrderByEnabled(True)
    layer.setRenderer(renderer)


def _memory_layer(geometry_name, layer_name, fields, features):
    uri = "%s?crs=EPSG:4326" % geometry_name
    layer = QgsVectorLayer(uri, layer_name, "memory")
    provider = layer.dataProvider()
    provider.addAttributes(fields.toList())
    layer.updateFields()
    copies = []
    for source in features:
        feature = QgsFeature(layer.fields())
        if source.hasGeometry():
            feature.setGeometry(source.geometry())
        feature.setAttributes(source.attributes())
        copies.append(feature)
    provider.addFeatures(copies)
    layer.updateExtents()
    return layer


def add_observations(collection, title, canvas=None, project=None, deployment_id=None):
    """Add one memory layer per geometry type and zoom the canvas to them.

    Returns {"total", "without_geometry", "layers"}.
    """
    project = project or QgsProject.instance()
    ensure_osm_basemap(project)

    text = json.dumps(cs_api.flatten_feature_collection(collection))
    fields = QgsJsonUtils.stringToFields(text)
    features = QgsJsonUtils.stringToFeatureList(text, fields)

    by_type = {}
    for feature in features:
        if feature.hasGeometry() and not feature.geometry().isEmpty():
            key = QgsWkbTypes.displayString(feature.geometry().wkbType())
        else:
            key = "None"
        by_type.setdefault(key, []).append(feature)

    group = _replace_group(project, GROUP_PREFIX + title)
    extent = QgsRectangle()
    extent.setNull()
    layers = []
    for geometry_name, members in sorted(by_type.items()):
        suffix = "" if len(by_type) == 1 else " (%s)" % ("no geometry" if geometry_name == "None" else geometry_name)
        layer = _memory_layer(geometry_name, title + suffix, fields, members)
        if geometry_name.replace("Multi", "").startswith("Point"):
            _style_points(layer)
        layer.setCustomProperty(LAYER_PROPERTY, True)
        if deployment_id is not None:
            layer.setCustomProperty(DEPLOYMENT_PROPERTY, str(deployment_id))
        project.addMapLayer(layer, False)
        group.addLayer(layer)
        layers.append(layer)
        if geometry_name != "None":
            extent.combineExtentWith(layer.extent())

    if canvas is not None and not extent.isNull():
        _zoom_to(canvas, project, extent)

    kinds = [f.attribute("kind") for f in features] if fields.indexOf("kind") >= 0 else []
    return {
        "total": len(features),
        "images": sum(1 for k in kinds if k == "image"),
        "without_geometry": len(by_type.get("None", [])),
        "layers": layers,
    }


def deployment_layers(deployment_id, project=None):
    project = project or QgsProject.instance()
    return [
        layer for layer in project.mapLayers().values()
        if isinstance(layer, QgsVectorLayer) and layer.customProperty(DEPLOYMENT_PROPERTY) == str(deployment_id)
    ]


def observation_hashes(deployment_id, project=None):
    """{observation_id: {anchorHash, chainHash}} of the deployment's layers on the map; empty when none is drawn."""
    hashes = {}
    for layer in deployment_layers(deployment_id, project):
        fields = layer.fields()
        if fields.indexOf("observation_id") < 0:
            continue
        has_anchor = fields.indexOf("anchorHash") >= 0
        has_chain = fields.indexOf("chainHash") >= 0
        for feature in layer.getFeatures():
            obs_id = feature.attribute("observation_id")
            if obs_id in (None, ""):
                continue
            hashes[str(obs_id)] = {
                "anchorHash": _text_or_none(feature.attribute("anchorHash")) if has_anchor else None,
                "chainHash": _text_or_none(feature.attribute("chainHash")) if has_chain else None,
            }
    return hashes


def mark_chain_results(deployment_id, statuses, project=None):
    """Write each observation's verification result into the chain_check column. Returns the count written."""
    written = 0
    for layer in deployment_layers(deployment_id, project):
        provider = layer.dataProvider()
        if layer.fields().indexOf(CHAIN_FIELD) < 0:
            provider.addAttributes([_string_field(CHAIN_FIELD)])
            layer.updateFields()
        index = layer.fields().indexOf(CHAIN_FIELD)
        if index < 0 or layer.fields().indexOf("observation_id") < 0:
            continue
        changes = {}
        for feature in layer.getFeatures():
            status = statuses.get(str(feature.attribute("observation_id")))
            changes[feature.id()] = {index: status}
            written += status is not None
        provider.changeAttributeValues(changes)
        layer.triggerRepaint()
    return written


def _string_field(name):
    from qgis.core import QgsField
    try:
        from qgis.PyQt.QtCore import QMetaType
        return QgsField(name, QMetaType.Type.QString)
    except (ImportError, AttributeError, TypeError):  # older QGIS builds take a QVariant type
        from qgis.PyQt.QtCore import QVariant
        return QgsField(name, QVariant.String)


def _text_or_none(value):
    if value is None:
        return None
    text = str(value)
    return None if text in ("", "NULL") else text


def _zoom_to(canvas, project, extent):
    if extent.width() == 0 and extent.height() == 0:
        extent.grow(0.005)
    source = QgsCoordinateReferenceSystem("EPSG:4326")
    target = canvas.mapSettings().destinationCrs()
    if target.isValid() and target != source:
        extent = QgsCoordinateTransform(source, target, project).transformBoundingBox(extent)
    extent.scale(1.2)
    canvas.setExtent(extent)
    canvas.refresh()
