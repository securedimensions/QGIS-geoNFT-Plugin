def classFactory(iface):
    from .plugin import GeoNftPlugin
    return GeoNftPlugin(iface)
