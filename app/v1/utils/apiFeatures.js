class APIFeatures {
  /*
    modelQuery: Model.find() 
    queryString: request.query
    */
  constructor(model, queryString) {
    this.Model = model;
    this.modelQuery = this.Model.find();
    this.queryString = queryString;
    this.schemaFields = Object.keys(model.schema.paths);
  }

  search() {
    const queryObj = { ...this.queryString };

    const queryArr = Object.keys(queryObj); // extract fields from queryString

    // ignore any non-schema fields
    queryArr.forEach((el) => {
      if (!this.schemaFields.includes(el)) delete queryObj[el];
    });
    let queryStr = JSON.stringify(queryObj).replace(
      /\b(eq|gte|gt|lte|lt)\b/g,
      (match) => `$${match}`
    );

    this.modelQuery = this.modelQuery.find(JSON.parse(queryStr)); // The default way in mongodb

    return this;
  }

  sort() {
    if (this.queryString.sort) {
      const sortBy = this.queryString.sort.split(',').join(' ');
      // sortBy can be a space-separated string, or a key-value json object
      this.modelQuery = this.modelQuery.sort(sortBy);
    } else {
      this.modelQuery = this.modelQuery.sort('-createdAt');
    }

    return this;
  }

  filter() {
    // filter the fields to be selected
    if (this.queryString.fields) {
      let fields = this.queryString.fields.split(',').join(' ');
      if (fields.includes('-')) {
        if (!fields.includes('-__v')) {
          fields = `-__v ${fields}`;
        }
      } else {
        fields = fields.replace('__v', '').replace('  ', ' ');
      }
      this.modelQuery = this.modelQuery.select(`${fields}`);
    } else {
      // excluding field __v
      this.modelQuery = this.modelQuery.select('-__v');
    }

    return this;
  }

  paginate() {
    // e.g. page=2&limit=10, 1-10, page 1
    const page = this.queryString.page * 1 || 1; // pages: array starts with 0
    const limit = this.queryString.limit * 1 || 100; // limit: results per page

    const skipCount = (page - 1) * limit;
    this.modelQuery = this.modelQuery.skip(skipCount).limit(limit);

    if (this.queryString.page) {
      const numDocs = this.model.countDocuments();
      if (skipCount >= numDocs)
        throw new Error(`Page ${this.queryString.page} does not exist!`);
    }

    return this;
  }
} // end of class

module.exports = APIFeatures;
