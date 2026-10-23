const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

async function main() {
  const detections = [
    {conf:0.2, secondary:0.9, selected:true, inside:true, tile:0, idInTile:0, originalId:'secondary', address:'=1+1'},
    {conf:0.9, selected:false, inside:true, tile:0, idInTile:1, originalId:'unchecked'},
    {conf:0.9, selected:true, inside:false, tile:0, idInTile:2, originalId:'outside'},
    {conf:0.9, selected:false, inside:true, tile:0, idInTile:-1, address:'unchecked manual'},
  ].map(d => ({...d, getCenter:()=>[-75,40]}));
  const blobs=[], revoked=[], requests=[];
  const document = {body:{appendChild(e){e.parentNode=this;},removeChild(e){e.parentNode=null;}},createElement(){return {click(){}};}};
  const context = {console,document,Detection_detections:detections,Detection_minConfidence:0.5,
    Tile_tiles:[{id:0}],reviewCheckBox:{checked:false},confSlider:{value:50},getDistance:()=>0,currentMap:{getCenter:()=>[-75,40]},
    providerManager:{getDetections:()=>detections,getDetectionsArrayDirect:()=>detections,getTilesArrayDirect:()=>[]},
    Blob:class {constructor(parts,options){this.parts=parts;this.type=options.type;blobs.push(this);}},
    FormData:class {constructor(){this.values={};}append(k,v){this.values[k]=v;}},
    fetch:async (url,request)=>{requests.push(request);return {ok:true,blob:async()=>({size:10})};},
    alert(){},setTimeout(f){f();},window:{document,Detection_detections:detections,TowerScoutLogger:{debug(){}},URL:{createObjectURL:()=>`blob:${blobs.length}`,revokeObjectURL:u=>revoked.push(u)}}};
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../../webapp/js/src/ui/export.js'),'utf8'),context);
  context.window.download_kml();
  assert.strictEqual(blobs.length,1,'selected visible secondary-qualified result must be exported');
  assert.match(blobs[0].parts.join(''), /<name>=1\+1<\/name>/);
  context.reviewCheckBox.checked=true;
  context.window.download_csv();
  const csv=blobs[1].parts.join('');
  assert.strictEqual(csv.charCodeAt(0),0xfeff,'CSV must identify UTF-8 to Excel');
  assert.match(csv,/0,true,true,true,/,'threshold agrees with displayed secondary score');
  assert.match(csv,/2,true,false,true,/,'review mode does not falsify inside_boundary');
  assert.match(csv,/"'=1\+1"/,'spreadsheet formulas are literal text');
  context.reviewCheckBox.checked=false;
  context.window.download_dataset();
  await new Promise(resolve=>setImmediate(resolve));
  assert.strictEqual(requests.length,1);
  assert.deepStrictEqual(JSON.parse(requests[0].body.values.include).map(d=>d.id),['secondary','outside']);
  assert.deepStrictEqual(JSON.parse(requests[0].body.values.additions),[],'unchecked manual towers stay excluded');
  assert.strictEqual(revoked.length,3,'all download URLs are released');
  detections[0].address='A\u0000B\u000bC';
  context.window.download_kml();
  assert.match(blobs.at(-1).parts.join(''),/<name>ABC<\/name>/,'XML-invalid controls are removed');
  console.log('Task-106 selected export, boundary, encoding and download lifetime checks passed');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
