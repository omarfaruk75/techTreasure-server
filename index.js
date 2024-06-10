const express = require('express')
const app = express()
require('dotenv').config()
const cors = require('cors')
const cookieParser = require('cookie-parser')
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion,ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken')
const morgan = require('morgan')
const port = process.env.PORT || 5000;


//middleware

const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true,
  optionSuccessStatus: 200,
}
app.use(cors(corsOptions))
app.use(express.json())
app.use(cookieParser())
app.use(morgan('dev'))


 const verifyToken = (req, res, next) => {
      // console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'unauthorized access' })
        }
        req.decoded = decoded;
        next();
      })
    }


const uri = `mongodb+srv://${process.env.DB_USER_TECH}:${process.env.DB_PASS_TECH}@cluster0.2lcaz14.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    const reviewsCollection = client.db('techTreasure').collection('reviews');
    const usersCollection = client.db('techTreasure').collection('users');
    const productsCollection = client.db('techTreasure').collection('products');
    const reportsCollection = client.db('techTreasure').collection('reports');
    const votesCollection = client.db('techTreasure').collection('votes');
    const paymentsCollection = client.db("techTreasure").collection("payments");


//verify admin
  const verifyAdmin = async (req,res,next)=>{
  const user=req.user;
  const query={email:user?.email}
  const result = await usersCollection.findOne(query)
  if(!result||result?.role!=="admin") return res.status(401).send({message:"unauthorized access"})
next()
  }
//verifyHost middleware
const verifyModerator = async (req,res,next)=>{
  const user=req.user;
  const query={email:user?.email}
  const result = await usersCollection.findOne(query)
  if(!result||result?.role!=="moderator") return res.status(401).send({message:"unauthorized access"})
next()
  }

    
//get review for ui
app.get('/reviews',async(req,res)=>{
    const result=await reviewsCollection.find().toArray();
    res.send(result)
})
//post a review
app.post('/review',async(req,res)=>{
    const review=req.body;
    const result=await reviewsCollection.insertOne(review);
    res.send(result)
})

// Endpoint to get product details along with its reviews
app.get('/product-details-with-reviews/:id', async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const product = await productsCollection.findOne(query);

    if (product) {
        const query = { productName: product.productName };
        const reviews = await reviewsCollection.find(query).toArray();
        res.send({ product, reviews });
    } else {
        res.status(404).send({ message: 'Product not found' });
    }
});


    // auth related api
    app.post('/jwt', async (req, res) => {
      const user = req.body
      console.log('I need a new jwt', user)
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '365d',
      })
      res
        .cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })
        .send({ success: true })
    })
 
    // save a user data in db

    app.put('/user', async (req, res) => {
      const user = req.body
      const query = { email: user?.email }
      // check if user already exists in db
      const isExist = await usersCollection.findOne(query)
      if (isExist) {
        if (user.status === 'Requested') {
          // if existing user try to change his role
          const result = await usersCollection.updateOne(query, {
            $set: { status: user?.status },
          })
          return res.send(result)
        } else {
          // if existing user login again
          return res.send(isExist)
        }
      }

      // save user for the first time
      const options = { upsert: true }
      const updateDoc = {
        $set: {
          ...user,
          timestamp: Date.now(),
        },
      }
      const result = await usersCollection.updateOne(query, updateDoc, options)
      res.send(result)
    })

//payment intent

 app.post("/create-payment-inten", async (req, res) => {
  const { price } = req.body;
  const amount = parseInt(price*100)
  console.log(amount);
  const paymentIntent = await stripe.paymentIntents.create({
    amount:amount,
    currency:'usd',
    payment_method_types: ["card" ],
  })
    res.send({clientSecret: paymentIntent.client_secret})
  });
  //
  app.post('/payments',async(req,res)=>{
  const payment=req.body;
  const paymentsResult= await paymentsCollection.insertOne(payment);
  //carefully delete each item from the cart
console.log('payment info', payment);

res.send(paymentsResult)
})


app.get('/payment/status/:email', async (req, res) => {
    const email = req.params.email;
    const payment = await paymentsCollection.findOne({ email, status: 'Verified' });
    res.send({ status: payment ? 'Verified' : 'Not Verified', amount: payment ? payment.price : 200 });
});


    // get a user info by email from db
    app.get('/user/:email', async (req, res) => {
      const email = req.params.email
      const result = await usersCollection.findOne({ email })
      res.send(result)
    })

    // get all users data from db
//app.get('/users', verifyToken, verifyAdmin, async (req, res) => 

    app.get('/users', async (req, res) => {
      const result = await usersCollection.find().toArray()
      res.send(result)
    })

    //update a user role
    app.patch('/users/update/:email', async (req, res) => {
      const email = req.params.email
      const user = req.body
      const query = { email }
      const updateDoc = {
        $set: { ...user, timestamp: Date.now() },
      }
      const result = await usersCollection.updateOne(query, updateDoc)
      res.send(result)
    })

    //search product data
    app.get("/product", async (req, res) => {
    const search = req.query.search;
    let query = {};

    if (search) {
        query = {
            tagsItem: {
                $regex: search,
                $options: 'i'
            }
        };
    }

    try {
        const result = await productsCollection.find(query).toArray();
        res.send(result);
    } catch (error) {
        console.error("Error fetching Products:", error);
        res.status(500).json({ error: "Error fetching products" });
    }
});

app.get('/productsCount', async (req, res) => {
  const count = await productsCollection.countDocuments({ status: 'Accepted' });
  res.send({ count });
});

//get review for ui
app.get('/product',async(req,res)=>{
  const page=parseInt(req.query.page);
  const size=parseInt(req.query.size);
  console.log(page,size);
  const result=await productsCollection.find()
  .skip(page * size)
  .limit(size)
  .toArray();
  res.send(result)
})
app.post('/product',async(req,res)=>{
  const product =req.body;
  const result = await productsCollection.insertOne(product);
  res.send(result)

})


// app.get('/admin-stats',verifyToken,verifyAdmin,async(req,res)=>{
app.get('/admin-stats',async(req,res)=>{
  const users=await usersCollection.estimatedDocumentCount();
  const reviews=await reviewsCollection.estimatedDocumentCount();
  const products=await productsCollection.estimatedDocumentCount();
  //this is the not best way
  // const payments = await paymentsCollection.find().toArray();
  // const revenue= payments.reduce((total,payment)=>total+payment.price,0)
  
  res.send({users,reviews,products});
})


//for report post
app.post('/report/:id', async (req, res) => {
    const productId = req.params.id;

    try {
        // Create the report document
        const report = {
            productId: new ObjectId(productId),
            timestamp: new Date(),
            status: 'reported'
        };

        // Insert the report into the reports collection
        const result = await reportsCollection.insertOne(report);

        res.status(201).json({ message: 'Product reported successfully', report });
    } catch (error) {
        console.error('Error reporting product:', error);
        res.status(500).json({ message: 'Failed to report product. Please try again later.' });
    }
});


app.get('/report-status/:productId', async (req, res) => {
    const { productId } = req.params;

    try {
        const report = await reportsCollection.findOne({ productId: new ObjectId(productId) });
        if (report) {
            res.status(200).json({ status: report.status });
        } else {
            res.status(404).json({ message: 'Report not found' });
        }
    } catch (error) {
        console.error('Error fetching report status:', error);
        res.status(500).json({ message: 'Failed to fetch report status. Please try again later.' });
    }
});


//to get data for tabular 
app.get('/products/:email',async(req,res)=>{
  const email=req.params.email
  const query={'productOwner.email':email} 
  const result=await productsCollection.find(query).toArray()
  res.send(result);

})
app.get('/product/:id',async(req,res)=>{
    const id = req.params.id
    const query = { _id:new ObjectId(id)}
    const result = await productsCollection.findOne(query)
    console.log(result)
    res.send(result)
})
app.get('/product-details/:id',async(req,res)=>{
    const id = req.params.id
    const query = { _id:new ObjectId(id)}
    const result = await productsCollection.findOne(query)
    console.log(result)
    res.send(result)
})

//report post for a product
app.post('/report-product', async (req, res) => {
    const { productId } = req.body;
    // You can add more information like userId if needed
    const report = {
        productId: new ObjectId(productId),
        timestamp: new Date(),
        status: 'pending', // Initial status of the report
    };

    const result = await reportsCollection.insertOne(report);
    res.send(result);
});

//update a product status
app.patch('/product/update/:id',async(req,res)=>{
  const productItem=req.body;
  const id=req.params.id;
  const query={_id:new ObjectId(id)}
  const updatedDoc={
    $set:{
          ...productItem
    }
  }
  const result=await productsCollection.updateOne(query,updatedDoc);
  res.send(result);
})


//update a product
app.patch('/product/:id',async(req,res)=>{
  const productItem=req.body;
  const id=req.params.id;
  const query={_id:new ObjectId(id)}
  const updatedDoc={
    $set:{
          // productName:productItem.productName,
          // productDetails:productItem.productDetails,
          // tagsItem:productItem.tagsItem,
          // image:productItem.image,
          // timestamp:productItem.timestamp
          ...productItem
    }
  }
  const result=await productsCollection.updateOne(query,updatedDoc);
  res.send(result);
})
//vote count api
app.put('/product-vote/votes/:id', async (req, res) => {
    const voteType = req.body.voteType;
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const updateDoc = {
        $inc: {
            upvotes: voteType === 'upvoted' ? 1 : 0,
            downvotes: voteType === 'downvoted' ? 1 : 0
        }
    };

    try {
        const result = await votesCollection.updateOne(query, updateDoc);
        if (result.modifiedCount > 0) {
            const updatedDocument = await votesCollection.findOne(query);
            res.send({
                upvotes: updatedDocument.upvotes,
                downvotes: updatedDocument.downvotes
            });
        } else {
            res.status(400).send('Failed to update vote');
        }
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});


//for vote count// Patch endpoint for voting on a product// Patch endpoint for voting on a product
app.patch('/product/:id/vote', async (req, res) => {
  const id = req.params.id;
  const { voteType } = req.body; // Expecting 'upvote', 'downvote', or 'neutral' in the request body

  if (!voteType || !['upvote', 'downvote', 'neutral'].includes(voteType)) {
    return res.status(400).send({ message: 'Invalid vote type' });
  }

  const query = { _id: new ObjectId(id) };

  // Fetch current product to determine the current vote state
  const product = await productsCollection.findOne(query);
  if (!product) {
    return res.status(404).send({ message: 'Product not found' });
  }

  // Logic for updating the vote count
  let voteIncrement = 0;
  if (voteType === 'upvote') {
    voteIncrement = 1;
  } else if (voteType === 'downvote') {
    voteIncrement = -1;
  } else if (voteType === 'neutral') {
    // If current vote state is upvoted, reset by decrementing the vote
    if (product.currentVote === 'upvote') {
      voteIncrement = -1;
    } else if (product.currentVote === 'downvote') {
      voteIncrement = 1;
    }
  }

  // Update the product vote count and the currentVote state
  const update = {
    $inc: { voteCount: voteIncrement },
    $set: { currentVote: voteType === 'neutral' ? null : voteType }
  };
  const result = await productsCollection.updateOne(query, update);

  if (result.modifiedCount > 0) {
    const updatedProduct = await productsCollection.findOne(query);
    return res.send({ success: true, voteCount: updatedProduct.voteCount });
  } else {
    return res.status(404).send({ message: 'Product not found' });
  }
});




//delete a product

app.delete('/product/:id',async(req,res)=>{
const id=req.params.id;
const query = {_id:new ObjectId(id)}
const result=await productsCollection.deleteOne(query)
res.send(result);
})
app.delete('/product/reject/:id',async(req,res)=>{
const id=req.params.id;
const query = {_id:new ObjectId(id)}
const result=await productsCollection.deleteOne(query)
res.send(result);
})




    // await client.db("admin").command({ ping: 1 });
    // console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
  
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
  res.send('Hello from Tech Treasure')
})

app.listen(port, () => {
  console.log(`Tech Treasure is running on port ${port}`)
})
