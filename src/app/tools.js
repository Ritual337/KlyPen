import { initAnnotations } from '../annotations/index.js';
import { initDrawTool } from '../annotations/drawTool.js';
import { initGeoFileImport } from '../ui/geoFileImport.js';
import { initImageryBoxTool } from '../ui/imageryBoxTool.js';
import { createRecentImageryPanel } from '../ui/recentImagery.js';
import { installScopeMask, destroyScopeMask } from '../scopeMask.js';
import { installLayerReleaseTrim } from '../sceneCommandRelease.js';
import {
  installRenderGovernor,
  getRenderGovernorDiagnostics,
  governorRequestRender,
  holdContinuousRender,
  releaseContinuousRender,
} from '../renderGovernor.js';

/** Attach scene tools, rendering listeners and the application debug handle. */
export function createApplicationTools({
  scene,
  controls,
  data,
  loadingScreen,
  placeSearch,
  startChrome,
  signal,
  defer,
}) {
  const { viewer, tileset, mapStackController, operations } = scene;
  const { styleManager, weatherEffects, cockpitCloudEffects } = controls;
  const { dataManager } = data;
  const annotations = initAnnotations({
    viewer,
    tileset,
    placeSearch,
    resolver: operations.annotationResolver,
  });
  defer(() => {
    if (window.__gevAnnotations === annotations) delete window.__gevAnnotations;
    annotations.destroy();
  });
  const drawTool = initDrawTool({ viewer, annotations });
  defer(() => drawTool?.destroy());
  const geoFileImport = initGeoFileImport({
    viewer,
    navigation: styleManager,
    ground: operations.surface?.groundFloor,
    subscribeMapSource: (listener) => mapStackController?.subscribe?.(listener),
  });
  defer(() => geoFileImport?.destroy());
  const recentImagery = dataManager.layers.get('recent-imagery')?.module;
  if (recentImagery) {
    recentImagery.attachTileset(tileset);
    const imageryBoxTool = initImageryBoxTool({
      viewer,
      onBox: (box) => recentImagery.setBox(box),
      onCancel: (reason, message, box) => {
        if (message) recentImagery.reportBoxRefusal(message, box);
      },
      onActive: (active) => recentImagery.setToolActive(active),
      onEscape: () => recentImagery.clearPreview(),
    });
    data.presentation.attachRecentImagery((container) =>
      createRecentImageryPanel({
        container,
        viewer,
        layer: recentImagery,
        tool: imageryBoxTool,
      }),
    );
    const recentImageryHandle = { layer: recentImagery, tool: imageryBoxTool };
    window.__gevRecentImagery = recentImageryHandle;
    defer(() => {
      if (window.__gevRecentImagery === recentImageryHandle)
        delete window.__gevRecentImagery;
      data.presentation.attachRecentImagery(null);
      imageryBoxTool?.destroy();
    });
  }
  if (startChrome)
    defer(startChrome({ loadingScreen, styleManager, dataManager, signal }));
  installRenderGovernor(viewer);
  defer(
    installLayerReleaseTrim({
      scene: viewer.scene,
      dataManager,
      requestRender: governorRequestRender,
    }),
  );
  installScopeMask(viewer);
  defer(() => destroyScopeMask());
  const removeTrackingListener = viewer.trackedEntityChanged.addEventListener(
    () => {
      if (viewer.trackedEntity) holdContinuousRender('tracked-entity');
      else releaseContinuousRender('tracked-entity');
    },
  );
  const syncVisibilitySuspension = () => {
    const hidden = document.hidden;
    viewer.useDefaultRenderLoop = !hidden;
    cockpitCloudEffects?.setSuspended?.(hidden);
    if (!hidden) {
      data.presentation.flushVisible();
      governorRequestRender('visibility-restore');
    }
  };
  document.addEventListener('visibilitychange', syncVisibilitySuspension);
  defer(() =>
    document.removeEventListener('visibilitychange', syncVisibilitySuspension),
  );
  defer(() => {
    removeTrackingListener();
    releaseContinuousRender('tracked-entity');
  });
  syncVisibilitySuspension();
  window.__godsEyeView = {
    viewer,
    styleManager,
    tileset,
    dataManager,
    mapStackController,
    annotations,
    weatherEffects,
    cockpitCloudEffects,
    getRenderGovernorDiagnostics,
    surfaceServices: operations.surface,
    requestRender: governorRequestRender,
  };
  const debug = window.__godsEyeView;
  defer(() => {
    if (window.__godsEyeView === debug) delete window.__godsEyeView;
  });
  return { annotations };
}