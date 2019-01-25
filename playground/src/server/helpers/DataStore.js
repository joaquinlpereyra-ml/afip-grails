class DataStore {
  constructor(){
    this._data = [];
    this.catchingTime = 60000;
  }

  add(item){
    this._data.push(item);
    // Store received results for one minute
    setTimeout( () => {
      this._data.shift();
    }, this.catchingTime);
  }

  get(id){
  	const data = this._data.find(d => d.id === id);
  	this.delete(id);
    return data;
  }

  delete(id){
    const data = this._data.find(d => d.id === id)
    const index = this._data.indexOf(data);
    if (index > -1) {
      this._data.splice(index, 1);
    }
  }

  list(){
    return this._data;
  }
}

const instance = new DataStore();
Object.freeze(instance);

export default instance;