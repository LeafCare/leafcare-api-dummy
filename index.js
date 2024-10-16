import express from "express";
import {createDB} from "./db.js";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 3000;
const secretKey = "SECRET-KEY";

const userDB = createDB("data/users.json");
const potsDB = createDB("data/pots.json");
const plantsDB = createDB("data/plants.json");

app.use(express.json());

app.get("/", (req, res) => {
    res.json({message: "Hello from LeafCare API"});
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user by email
    const user = await userDB.findOneBy({ email });

    // Check if user exists and password matches
    if (!user || user.password !== password) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token with isAdmin field
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.isAdmin }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ token });
});

app.post('/users', async (req, res) => {
    const { first_name, last_name, email, password, isAdmin = false } = req.body;

    // Validate required fields
    if (!first_name || !last_name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email already exists
    const existingUser = await userDB.findOneBy({ email });
    if (existingUser) {
        return res.status(409).json({ error: 'Email already exists' });
    }

    // Save the new user
    const newUser = { first_name, last_name, email, password, isAdmin };
    await userDB.save(newUser);

    // Return created user without password
    const { password: _, ...createdUser } = newUser;
    res.status(201).json(createdUser);
});

app.get('/users', async (req, res) => {
    const { page = 1, limit = 30, name } = req.query;
    const token = req.headers.authorization?.split(' ')[1];

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    try {
        const decoded = jwt.verify(token, secretKey);
        if (!decoded || !decoded.isAdmin) {
            return res.status(403).json({ error: 'Forbidden: Admin access required' });
        }
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Search criteria for name
    const criteria = name ? { $or: [{ first_name: name }, { last_name: name }] } : {};
    const allUsers = await userDB.findBy(criteria);

    // Pagination
    const total_records = allUsers.length;
    const total_pages = Math.ceil(total_records / limit);
    const paginatedUsers = allUsers.slice((page - 1) * limit, page * limit);

    const response = {
        pagination: {
            total_records,
            total_pages,
            page: +page,
            limit: +limit
        },
        data: paginatedUsers.map(user => ({
            id: user.id,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email
        }))
    };

    res.status(200).json(response);
});

app.get('/users/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Check if user is admin or requesting their own info
    const user = await userDB.find(id);
    if (!user || (user.id !== decoded.id && !decoded.isAdmin)) {
        return res.status(404).json({ error: 'User not found or permission denied' });
    }

    // Return user info
    const { password: _, ...userInfo } = user; // Exclude password
    res.status(200).json(userInfo);
});

app.patch('/users/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;
    const { first_name, last_name, new_password, current_password } = req.body;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Find the user by ID
    const user = await userDB.find(id);
    if (!user || (user.id !== decoded.id && !decoded.isAdmin)) {
        return res.status(404).json({ error: 'User not found or permission denied' });
    }

    // Validate current password if new password is provided
    if (new_password && (!current_password || user.password !== current_password)) {
        return res.status(400).json({ error: 'Invalid current password' });
    }

    // Update user info
    if (first_name) user.first_name = first_name;
    if (last_name) user.last_name = last_name;
    if (new_password) user.password = new_password; // Update password

    await userDB.save(user); // Save the updated user info

    // Return updated user info excluding password
    const { password: _, ...updatedUser } = user;
    res.status(200).json(updatedUser);
});

app.delete('/users/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Check if the user is an admin
    if (!decoded.isAdmin) {
        return res.status(404).json({ error: 'Permission denied' });
    }

    // Find the user by ID
    const user = await userDB.find(id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Delete the user
    await userDB.delete(id);

    // Respond with no content status
    res.status(204).send();
});

app.post('/pots', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { code, pot_model_id } = req.body;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Check if the user is an admin
    if (!decoded.isAdmin) {
        return res.status(403).json({ error: 'Permission denied' });
    }

    // Validate required fields
    if (!code || !pot_model_id) {
        return res.status(400).json({ error: 'Code and pot_model_id are required' });
    }

    // Check if pot code already exists
    const existingPot = await potsDB.findOneBy({ code });
    if (existingPot) {
        return res.status(409).json({ error: 'Pot code already exists' });
    }

    // Create new pot object
    const newPot = { code, pot_model_id };
    await potsDB.save(newPot);

    // Return created pot info
    res.status(201).json(newPot);
});

app.get('/pots', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { page = 1, limit = 30 } = req.query;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Retrieve all pots
    const allPots = await potsDB.findAll();
    const total_records = allPots.length;
    const total_pages = Math.ceil(total_records / limit);
    const offset = (page - 1) * limit;

    // Determine which pots to return based on user permissions
    let pots;
    if (decoded.isAdmin) {
        // Admin can access all pots
        pots = allPots.slice(offset, offset + limit);
    } else {
        // Non-admin user can access only their pots
        pots = allPots.filter(pot => pot.userId === decoded.id).slice(offset, offset + limit); // Assuming pots have a userId property
    }

    if (pots.length === 0) {
        return res.status(403).json({ error: 'No pots found for this user' });
    }

    // Return paginated result
    res.status(200).json({
        pagination: {
            total_records,
            total_pages,
            page: Number(page),
            limit: Number(limit),
        },
        data: pots.map(pot => ({ id: pot.id, code: pot.code, pot_model: pot.pot_model_id })), // Adjust pot_model as needed
    });
});

app.get('/pots/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Find the pot by ID
    const pot = await potsDB.find(id);
    if (!pot || (pot.userId !== decoded.id && !decoded.isAdmin)) { // Assuming pots have a userId property
        return res.status(404).json({ error: 'Pot not found or permission denied' });
    }

    // Return pot info
    res.status(200).json(pot);
});

app.patch('/pots/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;
    const { code, pot_model_id } = req.body;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Check if the user is an admin
    if (!decoded.isAdmin) {
        return res.status(403).json({ error: 'Permission denied' });
    }

    // Find the pot by ID
    const pot = await potsDB.find(id);
    if (!pot) {
        return res.status(404).json({ error: 'Pot not found' });
    }

    // Update pot info
    if (code) pot.code = code;
    if (pot_model_id) pot.pot_model_id = pot_model_id;

    await potsDB.save(pot); // Save the updated pot info

    // Return updated pot info
    res.status(200).json(pot);
});

app.delete('/pots/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Check if the user is an admin
    if (!decoded.isAdmin) {
        return res.status(403).json({ error: 'Permission denied' });
    }

    // Find the pot by ID
    const pot = await potsDB.find(id);
    if (!pot) {
        return res.status(404).json({ error: 'Pot not found' });
    }

    // Delete the pot
    await potsDB.delete(id);

    // Respond with no content status
    res.status(204).send();
});

app.post('/plants', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { name } = req.body;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Validate plant name
    if (!name) {
        return res.status(400).json({ error: 'Plant name is required' });
    }

    // Check for unique name among user's plants
    const userPlants = await plantsDB.findBy({ userId: decoded.id }); // Assuming plants have a userId property
    if (userPlants.some(plant => plant.name === name)) {
        return res.status(409).json({ error: 'Plant name must be unique among user\'s plants' });
    }

    // Create new plant
    const newPlant = { name, userId: decoded.id }; // Adjust ID generation as needed
    await plantsDB.save(newPlant);

    // Return created plant info
    res.status(201).json(newPlant);
});

app.get('/plants', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { page = 1, limit = 30, name, user_name } = req.query;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Get all plants based on user role
    let userPlants;
    if (decoded.isAdmin) {
        userPlants = await plantsDB.findAll();
    } else {
        userPlants = await plantsDB.findBy({ userId: decoded.id });
    }

    // Filter by name if provided
    if (name) {
        userPlants = userPlants.filter(plant => plant.name.includes(name));
    }

    // Filter by user name if admin
    if (decoded.isAdmin && user_name) {
        userPlants = userPlants.filter(plant => plant.user_name === user_name); // Assuming plants have a user_name property
    }

    // Pagination
    const total_records = userPlants.length;
    const total_pages = Math.ceil(total_records / limit);
    const start = (page - 1) * limit;
    const end = start + limit;
    const paginatedPlants = userPlants.slice(start, end);

    // Return response
    res.status(200).json({
        pagination: {
            total_records,
            total_pages,
            page: Number(page),
            limit: Number(limit),
        },
        data: paginatedPlants,
    });
});

app.get('/plants/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Find the plant by ID
    const plant = await plantsDB.find(id);
    if (!plant) {
        return res.status(404).json({ error: 'Plant not found' });
    }

    // Check permissions
    if (plant.userId !== decoded.id && !decoded.isAdmin) {
        return res.status(403).json({ error: 'Permission denied' });
    }

    // Return plant info
    res.status(200).json(plant);
});

app.patch('/plants/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;
    const { name } = req.body;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Find the plant by ID
    const plant = await plantsDB.find(id);
    if (!plant) {
        return res.status(404).json({ error: 'Plant not found' });
    }

    // Check permissions
    if (plant.userId !== decoded.id) {
        return res.status(403).json({ error: 'Permission denied' });
    }

    // Update plant info
    if (name) {
        plant.name = name;
    }

    await plantsDB.save(plant);

    // Return updated plant info
    res.status(200).json(plant);
});

app.delete('/plants/:id', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { id } = req.params;

    // Check for token
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, secretKey);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Find the plant by ID
    const plant = await plantsDB.find(id);
    if (!plant) {
        return res.status(404).json({ error: 'Plant not found' });
    }

    // Check permissions
    if (plant.userId !== decoded.id) {
        return res.status(403).json({ error: 'Permission denied' });
    }

    // Delete the plant
    await plantsDB.delete(id);

    // Return no content response
    res.status(204).send();
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({message: "Server error. Check logs for more details"});
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
