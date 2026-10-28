/**
 * Style identifiers shared by the long-form share link (?style=…) and the
 * compact view codec. The 7-name list matches STYLE_PRESET_DEFAULTS in
 * src/ui/visualPresets.js. STYLE_URL_NAMES is identity today — kept as a map
 * so any consumer expecting the old shape keeps working.
 */
export const VIEW_STYLES = Object.freeze([
  'normal',
  'retro',
  'surveillance',
  'thermal',
  'anime',
  'noir',
  'snow',
]);

export const STYLE_URL_NAMES = Object.freeze({
  normal: 'normal',
  retro: 'retro',
  surveillance: 'surveillance',
  thermal: 'thermal',
  anime: 'anime',
  noir: 'noir',
  snow: 'snow',
});
