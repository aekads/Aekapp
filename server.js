const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const JWT_SECRET = "auth_token@321456987";
const fs = require("fs"); // To clean up temporary files

const app = express();
const pool = new Pool({
  user: "u3m7grklvtlo6",
  host: "35.209.89.182",
  database: "dbzvtfeophlfnr",
  password: "AekAds@24",
  port: 5432,
});




// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: "hp9537213@gmail.com",
        pass: "bnfd oupg gnvk npzx",
  },
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
// const upload = multer({ storage });
const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 }, // Max 10 MB
  fileFilter: (req, file, cb) => {
    // Accept only video files
    if (!file.mimetype.startsWith("video/")) {
      return cb(new Error("Only video files are allowed!"));
    }
    cb(null, true);
  },
  dest: "uploads/", // Temporary storage location
});


// Video upload API
// Video upload API with token validation
// Video upload API with token validation
app.post(
  "/api/upload-video",
  verifyToken,
  upload.single("video"),
  async (req, res) => {
    console.log("Headers:", req.headers);
    console.log("Body:", req.body);

    try {
      // Validate file
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "No video file uploaded.",
        });
      }

      console.log("File:", req.file);

      // Upload video to Cloudinary
      const cloudinaryResponse = await cloudinary.uploader.upload(
        req.file.path,
        {
          resource_type: "video", // Ensure the file is treated as a video
          folder: "uploaded_videos", // Optional: specify a folder in Cloudinary
        }
      );

      const videoUrl = cloudinaryResponse.secure_url;

      // Clean up the local temporary file
      fs.unlinkSync(req.file.path);

      console.log("Cloudinary Response:", cloudinaryResponse);

      // Save video details to the PostgreSQL database
      const query = `
          INSERT INTO video_uploads (userid, video_url)
          VALUES ($1, $2) RETURNING *;
      `;

      // Save with userid from the token (decoded in verifyToken)
      const dbResult = await pool.query(query, [req.user.userid, videoUrl]);

      console.log("Database Result:", dbResult.rows[0]);

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

      // Clean up the local temporary file if an error occurs
      if (req.file && req.file.path) {
        fs.unlinkSync(req.file.path);
      }

      res.status(500).json({
        success: false,
        message: "Error uploading video or saving to database.",
        error: err.message,
      });
    }
  }
);

// Middleware to handle Multer file upload errors
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        message: "File size exceeds 10 MB limit.",
      });
    }
  } else if (err.message === "Only video files are allowed!") {
    return res.status(400).json({
      success: false,
      message: err.message,
    });
  }
  next(err);
});
// Registration Page                                                              
// **GET /register**
app.get("/register", async (req, res) => {
  try {
      // Fetch screen IDs from the 'screens' table
      const result = await pool.query("SELECT screenid FROM public.screens");
      const screens = result.rows;
      res.render("register", { screens }); // Pass screen IDs to the template
  } catch (error) {
      console.error("Error fetching screens:", error);
      res.status(500).send("Internal Server Error");
  }
});

// **POST /register**
app.post("/register", async (req, res) => {
  const { userid, username, password, email, screenids } = req.body;

  try {
      // Validate input
      if (!screenids || screenids.length === 0) {
          return res.status(400).send("Please select at least one screen.");
      }
      if (!username || username.trim() === "") {
          return res.status(400).send("Username is required.");
      }
      if (!email || email.trim() === "") {
          return res.status(400).send("Email is required.");
      }

      // Ensure screenids is an array
      const formattedScreenIds = Array.isArray(screenids)
          ? screenids
          : [screenids];

      // Insert into database
      await pool.query(
          "INSERT INTO auth (userid, username, password, email, screenids) VALUES ($1, $2, $3, $4, $5)",
          [userid, username, password, email, formattedScreenIds]
      );

      // Send confirmation email
      const mailOptions = {
          from: "your_email@gmail.com", // Replace with your email
          to: email,
          subject: "Registration Successful",
          text: `
              Hello ${username},
              
              Thank you for registering!
              Here are your details:
              - User ID: ${userid}
             
              - Password: ${password}
              
              Regards,
              The Team
          `,
      };

      transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
              console.error("Error sending email:", error);
              return res.status(500).send("Registration successful, but failed to send email.");
          }
          console.log("Email sent: " + info.response);
          res.redirect("/success"); // Redirect to success page
      });
  } catch (err) {
      console.error("Error saving user data:", err);
      res.status(500).send("Error saving user data. User ID or email might already exist.");
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






// Function to generate 4-digit PIN
const generatePin = () => {
  return Math.floor(1000 + Math.random() * 9000).toString();
};

app.post("/api/forgot_password", async (req, res) => {
    const { userid } = req.body;

    // Validate input
    if (!userid) {
        return res.status(400).json({
            success: false,
            message: "UserID is required.",
        });
    }

    try {
        // Check if the userid exists in the database and fetch the email
        const result = await pool.query("SELECT email FROM auth WHERE userid = $1", [userid]);

        if (result.rows.length === 0) {
            console.error("UserID not found:", userid);
            return res.status(404).json({
                success: false,
                message: "UserID not found.",
            });
        }

        const { email } = result.rows[0];

        // Generate a new 4-digit PIN
        const newPin = generatePin();

        // Send the PIN to the user's email
        const mailOptions = {
            from: "your_email@gmail.com", // Replace with your email
            to: email,
            subject: "Your Password Reset PIN",
            text: `
                Hello,

                You requested a password reset.
                Your PIN for resetting your password is: ${newPin}

                Regards,
                The Team
            `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
                return res.status(500).json({
                    success: false,
                    message: "Error sending email.",
                });
            }
            console.log("Email sent: " + info.response);

            // Respond with success
            return res.json({
                success: true,
                message: "A 4-digit PIN has been sent to the registered email.",
            });
        });
    } catch (err) {
        console.error("Error handling password reset:", err);
        res.status(500).json({
            success: false,
            message: "An error occurred while processing your request.",
        });
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

  // Validate input
  if (!userid || !password) {
      return res.status(400).json({
          success: false,
          message: "UserID and Password are required.",
      });
  }

  try {
      // Query the database for user details
      const result = await pool.query(
          "SELECT password, username, status FROM auth WHERE userid = $1",
          [userid]
      );

      if (result.rowCount === 0) {
          return res.status(404).json({
              success: false,
              message: "UserID not found.",
          });
      }

      const { password: storedPassword, username } = result.rows[0];

      // Verify the password
      if (password !== storedPassword) {
          return res.status(401).json({
              success: false,
              message: "Incorrect password.",
          });
      }

      // Generate a JWT token
      const token = jwt.sign({ userid }, JWT_SECRET, { expiresIn: "1h" });

      // Update the user's status to 1 and save the token
      await pool.query(
          "UPDATE auth SET status = 1, token = $1 WHERE userid = $2",
          [token, userid]
      );

      // Respond with success, token, and additional user details
      res.json({
          success: true,
          message: "Password is correct. User logged in.",
          token,
          userid,
          username,
      });
  } catch (err) {
      console.error("Error during password check:", err);
      res.status(500).json({
          success: false,
          message: "Internal Server Error.",
      });
  }
});



//log-out
app.post("/api/logout", async (req, res) => {
  const authHeader = req.headers.authorization; // Authorization header

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
          success: false,
          message: "Authorization token is required.",
      });
  }

  const token = authHeader.split(" ")[1]; // Extract the token from the header

  try {
      // Decode the token to extract the user ID
      const decoded = jwt.verify(token, JWT_SECRET);
      const userid = decoded.userid;

      // Update the database: Invalidate the token and set status to 0
      const result = await pool.query(
          "UPDATE auth SET token = NULL, status = 0 WHERE userid = $1 AND token = $2 RETURNING userid",
          [userid, token]
      );

      if (result.rowCount === 0) {
          return res.status(404).json({
              success: false,
              message: "Invalid Token or UserID.",
          });
      }

      // Respond with success message
      res.json({
          success: true,
          message: "User successfully logged out.",
      });
  } catch (err) {
      console.error("Error during logout:", err);
      res.status(500).json({
          success: false,
          message: "Internal Server Error.",
      });
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
        END AS screentype,
        c.status,
        c.updated_at
      FROM 
        screens s
      INNER JOIN 
        device_configs d 
      ON 
        s.screenid = CAST(d.client_name AS INTEGER)
      LEFT JOIN
        client_statuses c
      ON 
        s.screenid = CAST(c.client_name AS INTEGER)
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

    // Modify the query to fetch data from the screen_proposal table
    const screenDetailsQuery = `
      SELECT 
        sp.screenid,
        screenname,
        sp.slot9,
        sp.slot9_clientname,
        sp.slot10,
        sp.slot10_clientname
      FROM 
        public.screen_proposal sp
      WHERE 
        sp.screenid = ANY($1::int[])
    `;

    const screenDetailsResult = await pool.query(screenDetailsQuery, [
      screenids,
    ]);

    if (screenDetailsResult.rows.length > 0) {
      // Map the result to rename fields
      const screensData = screenDetailsResult.rows.map(row => ({
        screenid: row.screenid,
        screenname: row.screenname,
        slot9: row.slot9,
        status_slot09: row.slot9_clientname, // Renamed field
        slot10: row.slot10,
        status_slot10: row.slot10_clientname, // Renamed field
      }));

      res.json({
        success: true,
        screensData,
      });
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

    // Prepare the new video data to be added
    const newVideoData = {
      id: video_Data.id,
      video_url: video_Data.video_url,
      uploaded_at: new Date().toISOString(),
      userid: video_Data.userid,
    };

    // Prepare the values for the slots
    const slotValue = JSON.stringify([newVideoData]);
    const slotClientName = "pending"; // Status for client slot

    // Iterate through each screenid and update the customer_screens_data table
    const updatedScreens = [];
    for (const screenid of screenids) {
      let customerScreensDataQuery;

      // Handle slot9 and slot10 explicitly in the query
      if (slot_number === "slot9") {
        customerScreensDataQuery = `
          INSERT INTO public.screen_proposal (screenid, slot9, slot9_clientname)
          VALUES ($1, $2, $3)
          ON CONFLICT (screenid) DO UPDATE
          SET slot9 = COALESCE(EXCLUDED.slot9, screen_proposal.slot9),
              slot9_clientname = COALESCE(EXCLUDED.slot9_clientname, screen_proposal.slot9_clientname)
          RETURNING screenid, slot9, slot9_clientname;
        `;
      } else if (slot_number === "slot10") {
        customerScreensDataQuery = `
          INSERT INTO public.screen_proposal (screenid, slot10, slot10_clientname)
          VALUES ($1, $2, $3)
          ON CONFLICT (screenid) DO UPDATE
          SET slot10 = COALESCE(EXCLUDED.slot10, screen_proposal.slot10),
              slot10_clientname = COALESCE(EXCLUDED.slot10_clientname, screen_proposal.slot10_clientname)
          RETURNING screenid, slot10, slot10_clientname;
        `;
      }
      
      // Execute the query
      const customerScreensResult = await pool.query(customerScreensDataQuery, [
        screenid, // $1
        slotValue, // $2
        slotClientName, // $3
      ]);
      

      // Collect the updated screen data
      updatedScreens.push(customerScreensResult.rows[0]);
    }

    // Respond with success and updated rows
    res.status(200).json({
      success: true,
      message: "Video data successfully set in the specified slot.",
      updatedScreens,
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
app.post("/api/delete-video-slot", verifyToken, async (req, res) => {
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
          FROM public.screen_proposal 
          WHERE screenid = ANY($1::int[])
      `;
    const existingDataResult = await pool.query(existingDataQuery, [screenids]);

    // Process each screen ID and delete the slot data
    const updatedScreens = [];
    for (const row of existingDataResult.rows) {
      // Determine fields to update based on slot_number
      let fieldsToUpdate = `${slot_number} = $1`;
      const values = [JSON.stringify([]), row.screenid]; // Clear slot data
      
      if (slot_number === "slot9") {
        fieldsToUpdate += ", slot9_clientname = $2";
        values.splice(1, 0, null); // Insert `null` for slot9_clientname
      } else if (slot_number === "slot10") {
        fieldsToUpdate += ", slot10_clientname = $2";
        values.splice(1, 0, null); // Insert `null` for slot10_clientname
      }

      // Update the database
      const updateQuery = `
              UPDATE public.screen_proposal 
              SET ${fieldsToUpdate}
              WHERE screenid = $3
              RETURNING screenid, ${slot_number};
          `;
      const updateResult = await pool.query(updateQuery, values);

      updatedScreens.push({
        id: updateResult.rows[0].screenid,
        // [slot_number]: JSON.parse(updateResult.rows[0][slot_number]),                 
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
                                                      
