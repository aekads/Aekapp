const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");

const jwt = require("jsonwebtoken");
const JWT_SECRET = "auth_token@321456987";

const app = express();
const pool = new Pool({
  user: "u3m7grklvtlo6",
  host: "35.209.89.182",
  database: "dbzvtfeophlfnr",
  password: "AekAds@24",
  port: 5432,
});

// sdfknj

const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { config } = require("dotenv");
// Load environment variables
config();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.json());

//auth middleware json token middleware
const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization; // Extract the Authorization header
    if (!authHeader) {
      return res
        .status(401)
        .json({ success: false, message: "Authorization header is required." });
    }

    const tokenParts = authHeader.split(" "); // Split the Bearer and token
    if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
      return res
        .status(400)
        .json({
          success: false,
          message: "Malformed token. Expected format: Bearer <token>.",
        });
    }

    const token = tokenParts[1]; // Extract the token

    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check the token in the database
    const result = await pool.query(
      "SELECT token FROM auth WHERE userid = $1",
      [decoded.userid]
    );

    if (result.rows.length === 0 || result.rows[0].token !== token) {
      return res
        .status(403)
        .json({ success: false, message: "Invalid or expired token." });
    }

    req.user = decoded; // Add user info to the request object
    next(); // Proceed to the next middleware or route
  } catch (err) {
    console.error("Token verification error:", err.message);
    res
      .status(403)
      .json({ success: false, message: "Invalid or expired token." });
  }
};

// Routes

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

// Video upload API
// Video upload API with token validation
// Video upload API with token validation
app.post(
  "/api/upload-video",
  verifyToken,
  upload.single("video"),
  async (req, res) => {
    try {
      // Validate file
      if (!req.file) {
        return res
          .status(400)
          .json({ success: false, message: "No video file uploaded." });
      }

      // Upload video to Cloudinary
      const result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: "video", // Ensure the file is treated as a video
        folder: "uploaded_videos", // Optional: specify a folder in Cloudinary
      });

      const videoUrl = result.secure_url;

      // Save video details to the PostgreSQL database
      const query = `
          INSERT INTO video_uploads (userid, video_url)
          VALUES ($1, $2) RETURNING *;
      `;

      // Save with userid from the token (decoded in verifyToken)
      const dbResult = await pool.query(query, [req.user.userid, videoUrl]);

      // Respond with success message and details
      res.status(200).json({
        success: true,
        message: "Video uploaded and saved successfully!",
        data: {
          video_data: dbResult.rows[0], // Include saved database record in the response
        },
      });
    } catch (err) {
      console.error("Error uploading video or saving to database:", err);
      res
        .status(500)
        .json({
          success: false,
          message: "Error uploading video or saving to database.",
        });
    }
  }
);

// Registration Page
app.get("/register", async (req, res) => {
  try {
    // Fetch screen IDs from the 'screens' table
    const result = await pool.query("SELECT screenid FROM public.screens");
    const screens = result.rows; // Extract rows from query result
    res.render("register", { screens }); // Pass to EJS template
  } catch (error) {
    console.error("Error fetching screens:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Handle Registration
// Handle Registration
app.post("/register", async (req, res) => {
  const { userid, username, password, screenids } = req.body;

  try {
    // Validate input
    if (!screenids || screenids.length === 0) {
      return res.status(400).send("Please select at least one screen.");
    }
    if (!username || username.trim() === "") {
      return res.status(400).send("Username is required.");
    }

    // Ensure screenids is an array
    const formattedScreenIds = Array.isArray(screenids)
      ? screenids
      : [screenids]; // If single value, convert to array

    // Insert into database
    await pool.query(
      "INSERT INTO auth (userid, username, password, screenids) VALUES ($1, $2, $3, $4)",
      [userid, username, password, formattedScreenIds]
    );

    res.redirect("/success");
  } catch (err) {
    console.error("Error saving user data:", err);
    res
      .status(500)
      .send("Error saving user data. User ID might already exist.");
  }
});

// Success Page
app.get("/success", (req, res) => {
  res.render("success");
});

// Login Page
app.get("/login", (req, res) => {
  res.render("login");
});

// Handle Login
app.get("/login", async (req, res) => {
  const { userid, password } = req.body;

  try {
    const user = await pool.query(
      "SELECT userid, screenids FROM auth WHERE userid = $1 AND password = $2",
      [userid, password]
    );

    if (user.rows.length > 0) {
      const { screenids } = user.rows[0];
      res.render("success", { userid, screenids });
    } else {
      res.status(401).send("Invalid User ID or Password.");
    }
  } catch (err) {
    console.error("Error logging in:", err);
    res.status(500).send("Internal Server Error");
  }
});

// User Check API
app.post("/api/check-user", async (req, res) => {
  console.log("Request received:", req.body);

  const { userid } = req.body;
  console.log("Received request:", req.body);
  try {
    if (!userid) {
      return res
        .status(400)
        .json({ success: false, message: "User ID is required." });
    }
    const result = await pool.query(
      "SELECT userid FROM auth WHERE userid = $1",
      [userid]
    );

    if (result.rows.length > 0) {
      res.json({ success: true, message: "User found." });
    } else {
      res.status(404).json({ success: false, message: "User not found." });
    }
  } catch (err) {
    console.error("Error checking user:", err);
    res.status(500).json({ success: false, message: "Internal Server Error." });
  }
});

// API to Check Password and Return Screen IDs                                                                   // API to Check UserID and Password and Return Screen IDs
app.post("/api/check-password", async (req, res) => {
  const { userid, password } = req.body;

  try {
    // Validate input
    if (!userid || !password) {
      return res.status(400).json({
        success: false,
        message: "UserID and Password are required.",
      });
    }

    // Query the database to check if the userid and password combination exists
    const result = await pool.query(
      "SELECT userid, username FROM auth WHERE userid = $1 AND password = $2",
      [userid, password]
    );

    if (result.rows.length > 0) {
      const { username } = result.rows[0];

      // Generate a new JWT token
      const token = jwt.sign({ userid, username }, JWT_SECRET, {
        expiresIn: "1h",
      });

      // Save the token in the database
      await pool.query("UPDATE auth SET token = $1 WHERE userid = $2", [
        token,
        userid,
      ]);

      // Respond to the client
      res.json({
        success: true,
        message: "User authenticated.",
        userid,
        username,
        token,
      });
    } else {
      res
        .status(404)
        .json({ success: false, message: "Invalid UserID or Password." });
    }
  } catch (err) {
    console.error("Error checking credentials:", err);
    res.status(500).json({ success: false, message: "Internal Server Error." });
  }
});

// API to Fetch Screen Details
  
//Check if screen id add fetch screen with json web token and screen name

app.post("/api/get-screen-details", verifyToken, async (req, res) => {
  const { userid } = req.body;

  if (req.user.userid !== userid) {
    return res
      .status(403)
      .json({ success: false, message: "Unauthorized access." });
  }

  try {
    if (!userid) {
      return res
        .status(400)
        .json({ success: false, message: "User ID is required." });
    }

    const userQuery = "SELECT screenids FROM public.auth WHERE userid = $1";
    const userResult = await pool.query(userQuery, [userid]);

    if (userResult.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    const screenids = userResult.rows[0].screenids;
    if (!Array.isArray(screenids) || screenids.length === 0) {
      return res
        .status(404)
        .json({
          success: false,
          message: "No screens associated with this user.",
        });
    }

    const screenDetailsQuery = `
      SELECT 
        s.screenid,
        s.screenname,
        CASE
          WHEN d.ifsecondscreenispresentondevice = 1 THEN 'single'
          WHEN d.ifsecondscreenispresentondevice = 2 THEN 'dual'
          ELSE 'unknown'
        END AS screentype
      FROM 
        screens s
      INNER JOIN 
        device_configs d 
      ON 
        s.screenid = CAST(d.client_name AS INTEGER)
      WHERE 
        s.screenid = ANY($1::int[])
    `;

    const screenDetailsResult = await pool.query(screenDetailsQuery, [
      screenids,
    ]);

    if (screenDetailsResult.rows.length > 0) {
      res.json({ success: true, screensData: screenDetailsResult.rows });
    } else {
      res
        .status(404)
        .json({ success: false, message: "No matching screen data found." });
    }
  } catch (err) {
    console.error("Error fetching screen details:", err);
    res.status(500).json({ success: false, message: "Internal Server Error." });
  }
});

app.post("/api/get-screen-data", verifyToken, async (req, res) => {
  const { userid } = req.body;

  if (req.user.userid !== userid) {
    return res
      .status(403)
      .json({ success: false, message: "Unauthorized access." });
  }

  try {
    if (!userid) {
      return res
        .status(400)
        .json({ success: false, message: "User ID is required." });
    }

    const userQuery = "SELECT screenids FROM public.auth WHERE userid = $1";
    const userResult = await pool.query(userQuery, [userid]);

    if (userResult.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    const screenids = userResult.rows[0].screenids;
    if (!Array.isArray(screenids) || screenids.length === 0) {
      return res
        .status(404)
        .json({
          success: false,
          message: "No screens associated with this user.",
        });
    }

    const screenDetailsQuery = `
      SELECT 
        s.screenid,
        s.screenname,
        s.slot9,
        s.slot10
      FROM 
        screens s
      WHERE 
        s.screenid = ANY($1::int[])
    `;

    const screenDetailsResult = await pool.query(screenDetailsQuery, [
      screenids,
    ]);

    if (screenDetailsResult.rows.length > 0) {
      res.json({ success: true, screensData: screenDetailsResult.rows });
    } else {
      res
        .status(404)
        .json({ success: false, message: "No matching screen data found." });
    }
  } catch (err) {
    console.error("Error fetching screen details:", err);
    res.status(500).json({ success: false, message: "Internal Server Error." });
  }
});

// API to set video data in specified slot for all screenids of a user
// API to set video data in slot9 or slot10 for all screenids of a user
// app.post("/api/set-video-slot", async (req, res) => {
//   const { userid, video_Data, slot_number } = req.body;

//   try {
//       // Validate input
//       if (!userid || !video_Data || !slot_number) {
//           return res.status(400).json({
//               success: false,
//               message: "User ID, video data, and slot number are required.",
//           });
//       }

//       // Ensure the slot number is either slot9 or slot10
//       if (slot_number !== "slot9" && slot_number !== "slot10") {
//           return res.status(400).json({
//               success: false,
//               message: "Invalid slot number. Only 'slot9' and 'slot10' are allowed.",
//           });
//       }

//       // Fetch screen IDs associated with the user
//       const userQuery = `
//           SELECT screenids
//           FROM public.auth
//           WHERE userid = $1
//       `;
//       const userResult = await pool.query(userQuery, [userid]);

//       if (userResult.rows.length === 0) {
//           return res.status(404).json({ success: false, message: "User not found." });
//       }

//       const screenids = userResult.rows[0].screenids;
//       if (!Array.isArray(screenids) || screenids.length === 0) {
//           return res.status(404).json({ success: false, message: "No screens associated with this user." });
//       }

//       // Update the slot for all associated screen IDs
//       const updateQuery = `
//           UPDATE public.screens
//           SET ${slot_number} = $1
//           WHERE screenid = ANY($2::int[])
//           RETURNING screenid, ${slot_number};
//       `;
//       const updateResult = await pool.query(updateQuery, [video_Data, screenids]);

//       // Check if any rows were updated
//       if (updateResult.rows.length === 0) {
//           return res.status(404).json({ success: false, message: "No matching screens found to update." });
//       }

//       // Respond with success and updated rows
//       res.status(200).json({
//           success: true,
//           message: "Video data successfully set in the specified slot.",
//           updatedScreens: updateResult.rows,
//       });
//   } catch (err) {
//       console.error("Error setting video data in slot:", err);
//       res.status(500).json({
//           success: false,
//           message: "Internal Server Error.",
//       });
//   }
// });
app.post("/api/set-video-slot", verifyToken, async (req, res) => {
  const { userid, video_Data, slot_number } = req.body;

  if (req.user.userid !== userid) {
    return res
      .status(403)
      .json({ success: false, message: "Unauthorized access." });
  }

  try {
    // Validate input
    if (!userid || !video_Data || !slot_number) {
      return res.status(400).json({
        success: false,
        message: "User ID, video data, and slot number are required.",
      });
    }

    // Ensure the slot number is either slot9 or slot10
    if (slot_number !== "slot9" && slot_number !== "slot10") {
      return res.status(400).json({
        success: false,
        message: "Invalid slot number. Only 'slot9' and 'slot10' are allowed.",
      });
    }

    // Fetch screen IDs associated with the user
    const userQuery = `
          SELECT screenids
          FROM public.auth
          WHERE userid = $1
      `;
    const userResult = await pool.query(userQuery, [userid]);

    if (userResult.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    const screenids = userResult.rows[0].screenids;
    if (!Array.isArray(screenids) || screenids.length === 0) {
      return res
        .status(404)
        .json({
          success: false,
          message: "No screens associated with this user.",
        });
    }

    // Fetch the existing data for slot_number
    const existingDataQuery = `
          SELECT screenid, ${slot_number}
          FROM public.screens
          WHERE screenid = ANY($1::int[])
      `;
    const existingDataResult = await pool.query(existingDataQuery, [screenids]);

    // Prepare the new video data to be added
    const newVideoData = {
      id: video_Data.id,
      video_url: video_Data.video_url,
      uploaded_at: new Date().toISOString(),
      userid: video_Data.userid,
    };

    // Process each screen ID and update the slot
    const updatedScreens = [];
    for (const row of existingDataResult.rows) {
      let existingSlotData;

      // Parse the slot data or initialize as an empty array
      try {
        existingSlotData = row[slot_number] ? JSON.parse(row[slot_number]) : [];
      } catch (error) {
        existingSlotData = []; // Handle invalid JSON data
      }

      if (!Array.isArray(existingSlotData)) {
        existingSlotData = []; // Ensure it's an array
      }

      existingSlotData.push(newVideoData); // Add new video data to the array

      // Update the database
      const updateQuery = `
              UPDATE public.screens
              SET ${slot_number} = $1
              WHERE screenid = $2
              RETURNING screenid, ${slot_number};
          `;
      const updateResult = await pool.query(updateQuery, [
        JSON.stringify(existingSlotData),
        row.screenid,
      ]);
      updatedScreens.push({
        id: updateResult.rows[0].screenid,
        [slot_number]: JSON.parse(updateResult.rows[0][slot_number]),
      });
    }

    // Respond with success and updated rows
    res.status(200).json({
      success: true,
      message: "Video data successfully set in the specified slot.",
      [slot_number]: updatedScreens,
    });
  } catch (err) {
    console.error("Error setting video data in slot:", err);
    res.status(500).json({
      success: false,
      message: "Internal Server Error.",
    });
  }
});

// Delete Video Slot API
app.delete("/api/delete-video-slot", verifyToken, async (req, res) => {
  const { userid, slot_number } = req.body;

  if (req.user.userid !== userid) {
    return res
      .status(403)
      .json({ success: false, message: "Unauthorized access." });
  }

  try {
    // Validate input
    if (!userid || !slot_number) {
      return res.status(400).json({
        success: false,
        message: "User ID and slot number are required.",
      });
    }

    // Ensure the slot number is either slot9 or slot10
    if (slot_number !== "slot9" && slot_number !== "slot10") {
      return res.status(400).json({
        success: false,
        message: "Invalid slot number. Only 'slot9' and 'slot10' are allowed.",
      });
    }

    // Fetch screen IDs associated with the user
    const userQuery = `
          SELECT screenids
          FROM public.auth
          WHERE userid = $1
      `;
    const userResult = await pool.query(userQuery, [userid]);

    if (userResult.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    const screenids = userResult.rows[0].screenids;
    if (!Array.isArray(screenids) || screenids.length === 0) {
      return res
        .status(404)
        .json({
          success: false,
          message: "No screens associated with this user.",
        });
    }

    // Fetch existing data for the specified slot
    const existingDataQuery = `
          SELECT screenid, ${slot_number}
          FROM public.screens
          WHERE screenid = ANY($1::int[])
      `;
    const existingDataResult = await pool.query(existingDataQuery, [screenids]);

    // Process each screen ID and delete the slot data
    const updatedScreens = [];
    for (const row of existingDataResult.rows) {
      // Clear the slot data (set to an empty array or null, depending on requirements)
      const updatedSlotData = JSON.stringify([]); // Set to an empty array

      // Update the database
      const updateQuery = `
              UPDATE public.screens
              SET ${slot_number} = $1
              WHERE screenid = $2
              RETURNING screenid, ${slot_number};
          `;
      const updateResult = await pool.query(updateQuery, [
        updatedSlotData,
        row.screenid,
      ]);

      updatedScreens.push({
        id: updateResult.rows[0].screenid,
        [slot_number]: JSON.parse(updateResult.rows[0][slot_number]),
      });
    }

    // Respond with success and updated rows
    res.status(200).json({
      success: true,
      message: "Video data successfully deleted from the specified slot.",
      [slot_number]: updatedScreens,
    });
  } catch (err) {
    console.error("Error deleting video data from slot:", err);
    res.status(500).json({
      success: false,
      message: "Internal Server Error.",
    });
  }
});

// Start Server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
