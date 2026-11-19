"""Map tool: click an observation dot to open its details."""

from qgis.core import QgsGeometry, QgsFeatureRequest, QgsProject, QgsRectangle, QgsWkbTypes
from qgis.gui import QgsMapTool, QgsMapToolEmitPoint
from qgis.PyQt.QtCore import QDate, QDateTime, QTime, Qt, QVariant

from . import observation_view
from .map_layers import LAYER_PROPERTY

MAX_HITS = 12


def _plain(value):
    """Attribute values as plain Python: NULL → None, dates → ISO text."""
    if value is None:
        return None
    if isinstance(value, QDateTime):
        return value.toString(Qt.DateFormat.ISODateWithMs) if value.isValid() else None
    if isinstance(value, (QDate, QTime)):
        return value.toString(Qt.DateFormat.ISODate) if value.isValid() else None
    if isinstance(value, QVariant):
        return None if value.isNull() else value.value()
    return value


def observation_layers(project=None):
    """Visible point layers this plugin drew."""
    project = project or QgsProject.instance()
    root = project.layerTreeRoot()
    for layer in project.mapLayers().values():
        if not layer.customProperty(LAYER_PROPERTY, False):
            continue
        if not hasattr(layer, "geometryType") or layer.geometryType() != QgsWkbTypes.GeometryType.PointGeometry:
            continue
        node = root.findLayer(layer.id())
        if node is not None and node.isVisible():
            yield layer


class InspectObservationsTool(QgsMapToolEmitPoint):
    """Left click: on_hits(list of observation property dicts), images first, then nearest."""

    def __init__(self, canvas, on_hits):
        super().__init__(canvas)
        self._on_hits = on_hits
        self.setCursor(Qt.CursorShape.WhatsThisCursor)

    def canvasReleaseEvent(self, event):
        if event.button() != Qt.MouseButton.LeftButton:
            return
        self._on_hits(self.observations_at(event.mapPoint()))

    def observations_at(self, map_point):
        radius = QgsMapTool.searchRadiusMU(self.canvas())
        map_rect = QgsRectangle(
            map_point.x() - radius, map_point.y() - radius, map_point.x() + radius, map_point.y() + radius
        )
        hits = []
        for layer in observation_layers():
            rect = self.toLayerCoordinates(layer, map_rect)
            point = QgsGeometry.fromPointXY(self.toLayerCoordinates(layer, map_point))
            names = layer.fields().names()
            request = QgsFeatureRequest().setFilterRect(rect).setLimit(MAX_HITS * 4)
            for feature in layer.getFeatures(request):
                properties = {name: _plain(feature[name]) for name in names}
                kind = properties.get("kind") or observation_view.kind_of(properties)
                properties["kind"] = kind
                distance = feature.geometry().distance(point) if feature.hasGeometry() else float("inf")
                hits.append((kind != observation_view.IMAGE, distance, properties))
        hits.sort(key=lambda hit: (hit[0], hit[1]))
        return [properties for _not_image, _distance, properties in hits[:MAX_HITS]]
