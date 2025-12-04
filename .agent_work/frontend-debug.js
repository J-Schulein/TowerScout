// Debug patch for Detection update method
// Add this to webapp/js/towerscout.js Detection.update() method

update(newMap) ;{
    // first, process any map UI change
    super.update(newMap)

    let meetsInside = reviewCheckBox.checked || this.inside;
    
    // DEBUG: Log all the condition values
    console.log(`Detection ${this.id} update conditions:`, {
        selected: this.selected,
        conf: this.conf,
        minConfidence: Detection_minConfidence,
        meetsConfidence: this.conf >= Detection_minConfidence,
        inside: this.inside,
        reviewMode: reviewCheckBox.checked,
        meetsInside: meetsInside,
        finalVisible: this.selected && this.conf >= Detection_minConfidence && meetsInside
    });
    
    // then update by confidence
    this.map.updateMapRect(this, this.selected && this.conf >= Detection_minConfidence && meetsInside);
}