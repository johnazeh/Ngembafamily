require("dotenv").config();
const express = require("express");
const sql = require("mssql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // serve frontend

// ---------------- DATABASE CONFIG ----------------
const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  port: 1433,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: false
  }
};

// ---------------- INITIALIZE PASSWORDS ----------------
async function initializePasswords() {
  try {
    const pool = await sql.connect(config);
    const defaultHash = await bcrypt.hash("Welcome123", 10);

    await pool.request()
      .input("Password", sql.VarChar, defaultHash)
      .query(`
        UPDATE Members
        SET password = @Password, IsDefaultPassword = 1
        WHERE password IS NULL OR password = ''
      `);

    console.log("Default passwords initialized");
  } catch (err) {
    console.error("Error initializing passwords:", err);
  }
}

// Run only if enabled
if (process.env.INIT_PASSWORDS === "true") {
  initializePasswords();
}

// ---------------- LOGIN ----------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input("Email", sql.VarChar, email.toLowerCase())
      .query(`
        SELECT MemberID, FullName, Email, password, IsDefaultPassword
        FROM Members
        WHERE LOWER(Email) = @Email
      `);

    if (result.recordset.length === 0)
      return res.status(404).json({ error: "Email not found" });

    const member = result.recordset[0];
    const valid = await bcrypt.compare(password, member.password);

    if (!valid)
      return res.status(401).json({ error: "Invalid password" });

    if (member.IsDefaultPassword) {
      return res.json({
        MemberID: member.MemberID,
        Name: member.FullName,
        Email: member.Email,
        forceChange: true
      });
    }

    res.json({
      MemberID: member.MemberID,
      Name: member.FullName,
      Email: member.Email
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- CHANGE PASSWORD ----------------
app.post("/change-password", async (req, res) => {
  const { memberId, newPassword } = req.body;

  if (!memberId || !newPassword)
    return res.status(400).json({ error: "MemberID and new password required" });

  try {
    const pool = await sql.connect(config);
    const hash = await bcrypt.hash(newPassword, 10);

    await pool.request()
      .input("MemberID", sql.Int, memberId)
      .input("Password", sql.VarChar, hash)
      .query(`
        UPDATE Members
        SET password = @Password, IsDefaultPassword = 0
        WHERE MemberID = @MemberID
      `);

    res.json({ success: true, message: "Password updated successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- RESET PASSWORD ----------------
app.post("/reset-password", async (req, res) => {
  const { email } = req.body;

  if (!email)
    return res.status(400).json({ error: "Email is required" });

  try {
    const pool = await sql.connect(config);
    const defaultHash = await bcrypt.hash("Welcome123", 10);

    const result = await pool.request()
      .input("Email", sql.VarChar, email.toLowerCase())
      .input("Password", sql.VarChar, defaultHash)
      .query(`
        UPDATE Members
        SET password = @Password, IsDefaultPassword = 1
        WHERE LOWER(Email) = @Email
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "No member found with that email." });
    }

    res.json({ message: "Password reset. Use 'Welcome123' to log in." });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});

// ---------------- DASHBOARD ----------------
app.get("/dashboard/:memberId", async (req, res) => {
  const memberId = parseInt(req.params.memberId, 10);

  if (!memberId)
    return res.status(400).json({ error: "Invalid MemberID" });

  try {
    const pool = await sql.connect(config);

    // TODO: Insert your real RPN query here
    const rpnResult = await pool.request()
      .input("MemberID", sql.Int, memberId)
      .query(`
       WITH Raw AS (
            SELECT 
                PaymentID,
                PaymentType,
                TRY_CAST(AmountPaid AS DECIMAL(18,2)) AS Paid,
                TRY_CAST(AmountOwed AS DECIMAL(18,2)) AS Owed,
                PaymentDate
            FROM Payments
            WHERE MemberID = @MemberID
              AND LOWER(PaymentType) IN ('rpn-call', 'rpn-surplus')
        ),
        Ordered AS (
            SELECT *,
                ROW_NUMBER() OVER (ORDER BY PaymentDate ASC, PaymentID ASC) AS rn
            FROM Raw
        ),
        Ledger AS (
            SELECT 
                rn,
                PaymentID,
                PaymentType,
                Paid,
                Owed,
                PaymentDate,
                CASE WHEN LOWER(PaymentType) = 'rpn-surplus' THEN Paid ELSE 0 END AS SurplusIn,
                CASE WHEN LOWER(PaymentType) = 'rpn-call' THEN Paid ELSE 0 END AS CallIn
            FROM Ordered
        ),
        Calc AS (
            SELECT 
                rn,
                PaymentID,
                PaymentType,
                PaymentDate,
                SurplusIn,
                CallIn,
                SUM(SurplusIn - CallIn) OVER (ORDER BY rn ROWS UNBOUNDED PRECEDING) AS RunningSurplus
            FROM Ledger
        ),
        Final AS (
            SELECT TOP 1
                PaymentDate,
                CallIn AS RPNCallAmount,
                CASE 
                    WHEN RunningSurplus >= 0 THEN CallIn
                    ELSE CallIn + RunningSurplus
                END AS PaidRaw,
                RunningSurplus
            FROM Calc
            ORDER BY rn DESC
        ),
        Clean AS (
            SELECT
                'RPN-SCHEME' AS PaymentType,
                PaymentDate,
                RPNCallAmount,
                CASE WHEN PaidRaw < 0 THEN 0 ELSE PaidRaw END AS Paid,
                CASE 
                    WHEN RPNCallAmount - CASE WHEN PaidRaw < 0 THEN 0 ELSE PaidRaw END > 0
                    THEN RPNCallAmount - CASE WHEN PaidRaw < 0 THEN 0 ELSE PaidRaw END
                    ELSE 0
                END AS Owing,
                CASE WHEN RunningSurplus > 0 THEN RunningSurplus ELSE 0 END AS RPNBalance,
                CASE 
                    WHEN RPNCallAmount - CASE WHEN PaidRaw < 0 THEN 0 ELSE PaidRaw END = 0
                    THEN 'PAID'
                    ELSE 'OWING'
                END AS Status
            FROM Final
        )
        SELECT * FROM Clean;

      `);

    const otherPayments = await pool.request()
      .input("MemberID", sql.Int, memberId)
      .query(`
        SELECT 
          PaymentType,
          TRY_CAST(AmountPaid AS DECIMAL(18,2)) AS Paid,
          TRY_CAST(AmountOwed AS DECIMAL(18,2)) AS Owed,
          PaymentDate
        FROM Payments
        WHERE MemberID = @MemberID
          AND LOWER(PaymentType) IN ('project','registration','2025dues','fines','crydie')
        ORDER BY PaymentDate DESC
      `);

    res.json({
      rpn: rpnResult.recordset,
      otherPayments: otherPayments.recordset
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- START SERVER ----------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
