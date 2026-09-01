const DB_BINDING = "sos_db";

async function hashPassword(password) {
  if (!password) return null;

  const bytes = new TextEncoder().encode(password);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes
  );

  return Array.from(new Uint8Array(digest))
    .map(byte =>
      byte.toString(16).padStart(2, "0")
    )
    .join("");
}


function getDb(env) {
  return env[DB_BINDING];
}


function json(data, headers, status = 200) {
  return Response.json(data, {
    status,
    headers
  });
}


function normalizeStatus(status) {

  const value =
    String(status || "").toLowerCase();

  if (
    ![
      "pending",
      "approved",
      "rejected"
    ].includes(value)
  ) {
    throw new Error("Invalid status");
  }

  return value;
}


function isValidPhone(phone) {

  return (
    !phone ||
    /^\+?[0-9\s().-]{7,20}$/.test(
      String(phone).trim()
    )
  );
}


function validateMessage(message) {

  const length =
    String(message || "").trim().length;

  if (length < 10) {
    throw new Error(
      "Message must be at least 10 characters."
    );
  }

  if (length > 1000) {
    throw new Error(
      "Message must be 1000 characters or fewer."
    );
  }
}


function amountToCents(amount) {

  if (
    amount === undefined ||
    amount === null
  ) {
    throw new Error(
      "Donation amount is required."
    );
  }

  const text =
    String(amount).trim();

  if (!/^\d+(\.\d{1,2})?$/.test(text)) {
    throw new Error(
      "Donation amount must be a positive monetary value."
    );
  }

  const dollars =
    Number(text);

  if (!Number.isFinite(dollars) || dollars <= 0) {
    throw new Error(
      "Donation amount must be a positive monetary value."
    );
  }

  const rounded =
    Math.round(dollars * 100);

  if (rounded <= 0) {
    throw new Error(
      "Donation amount must be greater than zero."
    );
  }

  return rounded;
}



function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}


async function sendResendEmail(
  env,
  { to, replyTo, subject, html }
) {
  const apiKey = env.RESEND_API_KEY;

  if (!apiKey) {
    throw new Error("Resend API key not configured.");
  }

const fromAddress =
  env.EMAIL_FROM_ADDRESS || "Seeds of Success <noreply@soslearn.org>";

const response = await fetch(
  "https://api.resend.com/emails",
  {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: fromAddress,
      to: Array.isArray(to) ? to : [to],
      reply_to: replyTo,
      subject,
      html
    })
  }
);

  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `Resend API error (${response.status}): ${body}`
    );
  }

  return response.json();
}


async function sendContactEmail(env, { name, email, subject, message }) {
  const recipient = env.CONTACT_RECIPIENT_EMAIL;

  if (!recipient) {
    throw new Error("Contact recipient email not configured.");
  }

  return sendResendEmail(env, {
    to: recipient,
    replyTo: email,
    subject: `[Contact Form] ${subject}`,
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<h2 style="color:#0d6e4f">New Contact Form Submission</h2>',
      '<table style="width:100%;border-collapse:collapse">',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Name</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(name) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(email) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Subject</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(subject) + '</td></tr>',
      '</table>',
      '<h3 style="color:#0d6e4f;margin-top:24px">Message</h3>',
      '<p style="background:#f5faf8;padding:16px;border-radius:8px;line-height:1.7;white-space:pre-wrap">' + escapeHtml(message) + '</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success contact form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendVolunteerNotificationEmail(env, application) {
  const recipient = env.VOLUNTEER_NOTIFICATION_EMAIL;

  if (!recipient) {
    throw new Error("Volunteer notification recipient email not configured.");
  }

  return sendResendEmail(env, {
    to: recipient,
    replyTo: application.email,
    subject: "New Volunteer Registration - Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<h2 style="color:#0d6e4f">New Volunteer Registration</h2>',
      '<p style="color:#555;line-height:1.6">A new volunteer has submitted an application to Seeds of Success.</p>',
      '<table style="width:100%;border-collapse:collapse">',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Full Name</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.full_name) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.email) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Phone</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.phone || "") + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Role of Interest</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.role || "") + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Skills / Languages</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.skills || "") + '</td></tr>',
      '</table>',
      '<h3 style="color:#0d6e4f;margin-top:24px">Why They Want to Volunteer</h3>',
      '<p style="background:#f5faf8;padding:16px;border-radius:8px;line-height:1.7;white-space:pre-wrap">' + escapeHtml(application.message) + '</p>',
'<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success volunteer registration form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendContactConfirmationEmail(env, { name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Thank You for Contacting Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for contacting Seeds of Success!</p>',
      '<p style="color:#333;line-height:1.7">We have successfully received your message. Our team will review it and get back to you as soon as possible.</p>',
      '<p style="color:#333;line-height:1.7">We appreciate you reaching out and your interest in Seeds of Success.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success contact form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendVolunteerConfirmationEmail(env, { name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Volunteer Registration Received \u2013 Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for registering as a volunteer with Seeds of Success!</p>',
      '<p style="color:#333;line-height:1.7">We have successfully received your volunteer application. Our team will review your application and get back to you if any further information is required.</p>',
      '<p style="color:#333;line-height:1.7">We appreciate your interest in supporting Seeds of Success and making a difference.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success volunteer registration form.</p>',
      '</div>'
    ].join('')
  });
}


/* =========================================================
   STUDENT MAPPING
========================================================= */
function mapStudent(row) {

  const topics =
    row.topic_names
      ? row.topic_names
          .split("||")
          .filter(Boolean)
      : [];


  const topicScores =
    row.topic_scores
      ? row.topic_scores
          .split("||")
          .map(Number)
          .filter(Number.isFinite)
      : [];


  const completedTopics =
    Number(row.completed_topics || 0);


  const totalTopics =
    Number(row.total_topics || 0);


  const progress =
    totalTopics
      ? Math.round(
          (completedTopics / totalTopics) * 100
        )
      : 0;


  const averageMarks =
    topicScores.length
      ? Math.round(
          topicScores.reduce(
            (sum, score) => sum + score,
            0
          ) / topicScores.length
        )
      : 0;


  return {

    id: row.id,

    full_name: row.full_name,

    grade: row.grade,

    school: row.school,

    status: row.status,

    tutor_id: row.tutor_id,

    tutor_name: row.tutor_name,

    completed_sessions:
      Number(row.completed_sessions || 0),

    total_topics:
      totalTopics,

    completed_topics:
      completedTopics,

    progress,

    average_marks:
      averageMarks,

    completed_topic_names:
      topics,

    topic_scores:
      topicScores
  };
}



/* =========================================================
   GET STUDENTS
========================================================= */

async function getStudents(db) {

  const result =
    await db.prepare(`
      SELECT

        s.id,
        s.full_name,
        s.grade,
        s.school,
        s.status,

        ua.id AS tutor_id,
        ua.full_name AS tutor_name,

        COUNT(
          DISTINCT CASE
            WHEN ts.status = 'completed'
            THEN ts.id
          END
        ) AS completed_sessions,

        COUNT(
          DISTINCT st.id
        ) AS total_topics,

        COUNT(
          DISTINCT CASE
            WHEN st.completed_at IS NOT NULL
            THEN st.id
          END
        ) AS completed_topics,

        GROUP_CONCAT(
          CASE
            WHEN st.completed_at IS NOT NULL
            THEN st.topic_name
          END,
          '||'
        ) AS topic_names,

        GROUP_CONCAT(
          CASE
            WHEN st.completed_at IS NOT NULL
            THEN st.score
          END,
          '||'
        ) AS topic_scores

      FROM students s

      LEFT JOIN student_assignments sa
        ON sa.student_id = s.id
        AND sa.status = 'active'

      LEFT JOIN user_accounts ua
        ON ua.id = sa.tutor_id

      LEFT JOIN student_topics st
        ON st.student_id = s.id

      LEFT JOIN tutoring_sessions ts
        ON ts.student_id = s.id

      GROUP BY s.id

      ORDER BY s.full_name
    `).all();


  return (result.results || [])
    .map(mapStudent);
}



/* =========================================================
   GET TUTORS
========================================================= */

async function getTutors(db) {

  const result =
    await db.prepare(`
      SELECT

        ua.id,
        ua.full_name,
        ua.email,
        ua.phone,
        ua.status,

        COUNT(
          sa.student_id
        ) AS assigned_students

      FROM user_accounts ua

      LEFT JOIN student_assignments sa

        ON sa.tutor_id = ua.id

        AND sa.status = 'active'

      WHERE ua.role = 'tutor'

      GROUP BY ua.id

      ORDER BY ua.full_name
    `).all();


  return (result.results || []).map(row => ({

    id: row.id,

    full_name: row.full_name,

    email: row.email,

    phone: row.phone,

    status: row.status,

    assigned_students:
      Number(row.assigned_students || 0)

  }));
}



/* =========================================================
   GET VOLUNTEERS
========================================================= */

async function getVolunteers(db) {

  const result =
    await db.prepare(`
      SELECT

        ua.id,
        ua.full_name,
        ua.email,
        ua.phone,
        ua.status,
        ua.notification_message,

        vt.task_title AS current_task

      FROM user_accounts ua

      LEFT JOIN volunteer_tasks vt

        ON vt.volunteer_id = ua.id

        AND vt.status = 'open'

      WHERE ua.role = 'volunteer'

      ORDER BY ua.full_name
    `).all();


  return result.results || [];
}



/* =========================================================
   REPORTS
========================================================= */

async function getReports(db) {

  const students =
    await getStudents(db);


  const completedSessions =
    students.reduce(
      (sum, student) =>
        sum + student.completed_sessions,
      0
    );


  const averageProgress =
    students.length

      ? Math.round(

          students.reduce(
            (sum, student) =>
              sum + student.progress,
            0
          ) / students.length

        )

      : 0;


  const scoredStudents =
    students.filter(
      student =>
        student.average_marks > 0
    );


  const averageMarks =
    scoredStudents.length

      ? Math.round(

          scoredStudents.reduce(
            (sum, student) =>
              sum + student.average_marks,
            0
          ) / scoredStudents.length

        )

      : 0;


  const activePairs =
    students.filter(
      student =>
        student.tutor_id
    ).length;


  return {

    total_completed_sessions:
      completedSessions,

    average_student_progress:
      averageProgress,

    average_marks:
      averageMarks,

    active_tutor_student_pairs:
      activePairs,

    unassigned_students:
      students.length - activePairs,

    students
  };
}



/* =========================================================
   QUEUE NOTIFICATION
========================================================= */

async function queueNotification(
  db,
  {
    userId = null,
    email,
    message,
    now
  }
) {

  await db.prepare(`
    INSERT INTO notifications (

      id,

      recipient_user_id,

      recipient_email,

      message,

      status,

      created_at

    )

    VALUES (?, ?, ?, ?, ?, ?)

  `).bind(

    crypto.randomUUID(),

    userId,

    email,

    message,

    "queued",

    now

  ).run();
}



/* =========================================================
   CREATE USER AFTER APPROVAL
========================================================= */

async function createOrUpdateUserFromApplication(
  db,
  application,
  role,
  statusMessage,
  now
) {

  const existingUser =

    await db.prepare(`
      SELECT id

      FROM user_accounts

      WHERE email = ?
    `)

    .bind(application.email)

    .first();


  if (existingUser?.id) {

    await db.prepare(`
      UPDATE user_accounts

      SET

        full_name = ?,

        phone = ?,

        role = ?,

        status = ?,

        notification_message = ?,

        updated_at = ?

      WHERE id = ?
    `)

    .bind(

      application.full_name,

      application.phone || "",

      role,

      "active",

      statusMessage,

      now,

      existingUser.id

    )

    .run();


    return existingUser.id;
  }


  const userId =
    crypto.randomUUID();


  await db.prepare(`
    INSERT INTO user_accounts (

      id,

      full_name,

      email,

      phone,

      role,

      password_hash,

      status,

      notification_message,

      created_at,

      updated_at

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

  `)

  .bind(

    userId,

    application.full_name,

    application.email,

    application.phone || "",

    role,

    application.password_hash || null,

    "active",

    statusMessage,

    now,

    now

  )

  .run();


  return userId;
}



/* =========================================================
   CLOUDFLARE WORKER
========================================================= */

export default {

  async fetch(request, env) {


    const corsHeaders = {

      "Access-Control-Allow-Origin": "*",

      "Access-Control-Allow-Methods":
        "GET, POST, PATCH, DELETE, OPTIONS",

      "Access-Control-Allow-Headers":
        "Content-Type"
    };


    if (request.method === "OPTIONS") {

      return new Response(
        null,
        {
          headers: corsHeaders
        }
      );
    }


    const url =
      new URL(request.url);


    const db =
      getDb(env);



    try {


      /* =====================================================
         APPLICATION COUNT
      ===================================================== */

      if (

        url.pathname ===
          "/api/applications-count"

        &&

        request.method === "GET"

      ) {

        const result =

          await db

            .prepare(`
              SELECT COUNT(*) as count

              FROM volunteer_applications
            `)

            .first();


        return json(

          {

            success: true,

            applications:
              result.count

          },

          corsHeaders
        );
      }



      /* =====================================================
         VOLUNTEER APPLICATION SUBMISSION
      ===================================================== */

      if (

        url.pathname ===
          "/api/application"

        &&

        request.method === "POST"

      ) {

        const data =
          await request.json();

        const fullName =
          String(data.full_name || "").trim();

        const email =
          String(data.email || "").trim();

        if (
          fullName.length < 2
          ||
          fullName.length > 50
        ) {

          return json(

            {

              success: false,

              error:
                "Full name must be between 2 and 50 characters."

            },

            corsHeaders,

            400
          );
        }

        if (
          !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
            .test(email)
        ) {

          return json(

            {

              success: false,

              error:
                "Please enter a valid email address."

            },

            corsHeaders,

            400
          );
        }

        if (!isValidPhone(data.phone)) {

          return json(

            {

              success: false,

              error:
                "Phone number format is invalid."

            },

            corsHeaders,

            400
          );
        }


        validateMessage(
          data.message
        );


        const existingVolunteer =
          await db.prepare(`
            SELECT id

            FROM volunteer_applications

            WHERE email = ?

            LIMIT 1
          `)

          .bind(data.email)

          .first();


        if (existingVolunteer) {

          return json(

            {

              success: false,

              error:
                "An application with this email already exists. Please sign in or use a different email address."

            },

            corsHeaders,

            409
          );
        }


        await db.prepare(`
          INSERT INTO volunteer_applications (

            id,

            full_name,

            email,

            phone,

            role,

            skills,

            message,

            password_hash,

            status,

            created_at

          )

          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        `)

        .bind(

          crypto.randomUUID(),

          data.full_name,

          data.email,

          data.phone || "",

          data.role,

          data.skills || "",

          data.message,

          await hashPassword(
            data.password || ""
          ),

          "pending",

          new Date().toISOString()

        )

        .run();

        try {

          await sendVolunteerNotificationEmail(
            env,
            {
              full_name: fullName,
              email,
              phone: data.phone ? String(data.phone) : "",
              role: data.role || "",
              skills: data.skills || "",
              message: data.message
            }
          );

        } catch (emailError) {

          console.error(
            "Volunteer notification email failed:",
            emailError
          );
        }

        try {

          await sendVolunteerConfirmationEmail(
            env,
            {
              name: fullName,
              email
            }
          );

        } catch (emailError) {

          console.error(
            "Volunteer confirmation email failed:",
            emailError
          );
        }


        return json(

          {

            success: true,

            message:
              "Application submitted successfully"

          },

          corsHeaders
        );
      }



      /* =====================================================
         TUTOR SIGNUP
      ===================================================== */

      if (

        url.pathname ===
          "/api/tutor-signup"

        &&

        request.method === "POST"

      ) {

        const data =
          await request.json();


        if (!isValidPhone(data.phone)) {

          return json(

            {

              success: false,

              error:
                "Phone number format is invalid."

            },

            corsHeaders,

            400
          );
        }


        const existingTutor =

          await db.prepare(`
            SELECT id

            FROM tutor_applications

            WHERE email = ?

            LIMIT 1
          `)

          .bind(data.email)

          .first();


        if (existingTutor) {

          return json(

            {

              success: false,

              error:
                "A tutor application with this email already exists. Please sign in or use a different email address."

            },

            corsHeaders,

            409
          );
        }


        await db.prepare(`
          INSERT INTO tutor_applications (

            id,

            full_name,

            email,

            phone,

            skills,

            availability,

            password_hash,

            status,

            created_at

          )

          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

        `)

        .bind(

          crypto.randomUUID(),

          data.full_name,

          data.email,

          data.phone || "",

          data.skills || "",

          data.availability || "",

          await hashPassword(
            data.password || ""
          ),

          "pending",

          new Date().toISOString()

        )

        .run();


        return json(

          {

            success: true,

            message:
              "Tutor application submitted"

          },

          corsHeaders
        );
      }



      /* =====================================================
         ADMIN STATISTICS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/stats"

        &&

        request.method === "GET"

      ) {

        const [

          tutors,

          students,

          pendingVolunteers,

          pendingTutors,

          sessions

        ] = await Promise.all([


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM user_accounts

            WHERE role = 'tutor'
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM students
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM volunteer_applications

            WHERE status = 'pending'
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM tutor_applications

            WHERE status = 'pending'
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM tutoring_sessions

            WHERE status = 'completed'
          `).first()

        ]);


        return json(

          {

            success: true,

            stats: {

              total_tutors:
                tutors.count || 0,

              total_students:
                students.count || 0,

              pending_applications:

                (pendingVolunteers.count || 0)

                +

                (pendingTutors.count || 0),

              completed_sessions:
                sessions.count || 0

            }

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET VOLUNTEER APPLICATIONS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/volunteer-applications"

        &&

        request.method === "GET"

      ) {

        const result =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              role,

              skills,

              message,

              status,

              created_at,

              reviewed_at

            FROM volunteer_applications

            ORDER BY

              CASE status

                WHEN 'pending' THEN 0

                WHEN 'approved' THEN 1

                ELSE 2

              END,

              created_at DESC
          `)

          .all();


        return json(

          {

            success: true,

            applications:
              result.results || []

          },

          corsHeaders
        );
      }



      /* =====================================================
         VOLUNTEER APPROVE / REJECT
      ===================================================== */

      const volunteerStatusMatch =

        url.pathname.match(

          /^\/api\/admin\/volunteer-applications\/([^/]+)\/status$/

        );


      if (

        volunteerStatusMatch

        &&

        request.method === "PATCH"

      ) {

        const applicationId =

          decodeURIComponent(
            volunteerStatusMatch[1]
          );


        const { status } =
          await request.json();


        const normalizedStatus =
          normalizeStatus(status);


        const reviewedAt =
          new Date().toISOString();


        await db.prepare(`
          UPDATE volunteer_applications

          SET

            status = ?,

            reviewed_at = ?

          WHERE id = ?
        `)

        .bind(

          normalizedStatus,

          reviewedAt,

          applicationId

        )

        .run();


        const application =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              role,

              skills,

              message,

              password_hash,

              status,

              created_at,

              reviewed_at

            FROM volunteer_applications

            WHERE id = ?
          `)

          .bind(applicationId)

          .first();


        if (!application) {

          return json(

            {

              success: false,

              error:
                "Application not found"

            },

            corsHeaders,

            404
          );
        }


        let userId = null;

        let notificationMessage = "";


        if (
          normalizedStatus === "approved"
        ) {

          notificationMessage =
            "Your volunteer application has been approved. Thank you for joining Seeds of Success.";


          userId =

            await createOrUpdateUserFromApplication(

              db,

              application,

              "volunteer",

              "Your volunteer application has been approved.",

              reviewedAt
            );
        }


        else if (
          normalizedStatus === "rejected"
        ) {

          notificationMessage =
            "Thank you for applying to volunteer with Seeds of Success. At this time, your application was not selected.";
        }


        if (notificationMessage) {

          await queueNotification(

            db,

            {

              userId,

              email:
                application.email,

              message:
                notificationMessage,

              now:
                reviewedAt

            }

          );
        }


        return json(

          {

            success: true,

            application

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET TUTOR APPLICATIONS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/tutor-applications"

        &&

        request.method === "GET"

      ) {

        const result =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              skills,

              availability,

              message,

              status,

              created_at,

              reviewed_at

            FROM tutor_applications

            ORDER BY

              CASE status

                WHEN 'pending' THEN 0

                WHEN 'approved' THEN 1

                ELSE 2

              END,

              created_at DESC
          `)

          .all();


        return json(

          {

            success: true,

            applications:
              result.results || []

          },

          corsHeaders
        );
      }



      /* =====================================================
         TUTOR APPROVE / REJECT
      ===================================================== */

      const tutorStatusMatch =

        url.pathname.match(

          /^\/api\/admin\/tutor-applications\/([^/]+)\/status$/

        );


      if (

        tutorStatusMatch

        &&

        request.method === "PATCH"

      ) {

        const applicationId =

          decodeURIComponent(
            tutorStatusMatch[1]
          );


        const { status } =
          await request.json();


        const normalizedStatus =
          normalizeStatus(status);


        const reviewedAt =
          new Date().toISOString();


        await db.prepare(`
          UPDATE tutor_applications

          SET

            status = ?,

            reviewed_at = ?

          WHERE id = ?
        `)

        .bind(

          normalizedStatus,

          reviewedAt,

          applicationId

        )

        .run();


        const application =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              skills,

              availability,

              message,

              password_hash,

              status,

              created_at,

              reviewed_at

            FROM tutor_applications

            WHERE id = ?
          `)

          .bind(applicationId)

          .first();


        if (!application) {

          return json(

            {

              success: false,

              error:
                "Tutor application not found"

            },

            corsHeaders,

            404
          );
        }


        let userId = null;

        let notificationMessage = "";


        if (
          normalizedStatus === "approved"
        ) {

          notificationMessage =
            "Your tutor application has been approved. Welcome to Seeds of Success.";


          userId =

            await createOrUpdateUserFromApplication(

              db,

              application,

              "tutor",

              "Your tutor application has been approved.",

              reviewedAt
            );
        }


        else if (
          normalizedStatus === "rejected"
        ) {

          notificationMessage =
            "Thank you for applying as a tutor with Seeds of Success. At this time, your application was not selected.";
        }


        if (notificationMessage) {

          await queueNotification(

            db,

            {

              userId,

              email:
                application.email,

              message:
                notificationMessage,

              now:
                reviewedAt

            }

          );
        }


        return json(

          {

            success: true,

            application

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET APPROVED TUTORS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/tutors"

        &&

        request.method === "GET"

      ) {

        return json(

          {

            success: true,

            tutors:
              await getTutors(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET APPROVED VOLUNTEERS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/volunteers"

        &&

        request.method === "GET"

      ) {

        return json(

          {

            success: true,

            volunteers:
              await getVolunteers(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET STUDENTS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/students"

        &&

        request.method === "GET"

      ) {

        return json(

          {

            success: true,

            students:
              await getStudents(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         ASSIGN TUTOR TO STUDENT
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/assign-tutor"

        &&

        request.method === "POST"

      ) {

        const {

          student_id,

          tutor_id,

          assigned_by_admin_id

        } = await request.json();


        if (!student_id) {

          return json(

            {

              success: false,

              error:
                "student_id is required"

            },

            corsHeaders,

            400
          );
        }


        const now =
          new Date().toISOString();


        await db.prepare(`
          UPDATE student_assignments

          SET

            status = 'reassigned',

            updated_at = ?

          WHERE

            student_id = ?

            AND status = 'active'
        `)

        .bind(

          now,

          student_id

        )

        .run();


        if (tutor_id) {

          await db.prepare(`
            INSERT INTO student_assignments (

              id,

              student_id,

              tutor_id,

              assigned_by_admin_id,

              status,

              created_at,

              updated_at

            )

            VALUES (?, ?, ?, ?, ?, ?, ?)

          `)

          .bind(

            crypto.randomUUID(),

            student_id,

            tutor_id,

            assigned_by_admin_id || null,

            "active",

            now,

            now

          )

          .run();
        }


        return json(

          {

            success: true,

            students:
              await getStudents(db),

            tutors:
              await getTutors(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         REPORTS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/reports"

        &&

        request.method === "GET"

      ) {

        return json(

          {

            success: true,

            reports:
              await getReports(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         VOLUNTEER TASKS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/volunteer-tasks"

        &&

        request.method === "POST"

      ) {

        const data =
          await request.json();


        if (

          !data.volunteer_id

          ||

          !data.task_title

        ) {

          return json(

            {

              success: false,

              error:
                "volunteer_id and task_title are required"

            },

            corsHeaders,

            400
          );
        }


        const now =
          new Date().toISOString();


        const taskId =
          crypto.randomUUID();


        await db.prepare(`
          INSERT INTO volunteer_tasks (

            id,

            volunteer_id,

            assigned_by_admin_id,

            task_title,

            task_notes,

            due_at,

            status,

            created_at,

            updated_at

          )

          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

        `)

        .bind(

          taskId,

          data.volunteer_id,

          data.assigned_by_admin_id || null,

          data.task_title,

          data.task_notes || null,

          data.due_at || null,

          "open",

          now,

          now

        )

        .run();


        const task =

          await db.prepare(`
            SELECT

              vt.id,

              vt.volunteer_id,

              ua.full_name
                AS volunteer_name,

              ua.email
                AS recipient_email,

              vt.task_title,

              vt.task_notes,

              vt.due_at,

              vt.status,

              vt.created_at

            FROM volunteer_tasks vt

            JOIN user_accounts ua

              ON ua.id =
                 vt.volunteer_id

            WHERE vt.id = ?
          `)

          .bind(taskId)

          .first();


        await queueNotification(

          db,

          {

            userId:
              data.volunteer_id,

            email:
              task?.recipient_email || null,

            message:
              `New volunteer task assigned: ${data.task_title}`,

            now

          }

        );


        return json(

          {

            success: true,

            task

          },

          corsHeaders,

          201
        );
      }






      /* =====================================================
         CONTACT FORM SUBMISSION
      ===================================================== */

      if (
        url.pathname ===
          "/api/contact"
        &&
        request.method === "POST"
      ) {

        const data =
          await request.json();

        if (
          !data.full_name ||
          String(data.full_name).trim().length < 2
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter your full name (at least 2 characters)."
            },
            corsHeaders,
            400
          );
        }

        if (
          !data.email ||
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
            .test(
              String(data.email).trim()
            )
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter a valid email address."
            },
            corsHeaders,
            400
          );
        }

        if (
          !data.subject ||
          String(data.subject).trim().length < 2
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter a subject (at least 2 characters)."
            },
            corsHeaders,
            400
          );
        }

        if (
          !data.message ||
          String(data.message).trim().length < 10
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter a message (at least 10 characters)."
            },
            corsHeaders,
            400
          );
        }

        await sendContactEmail(
          env,
          {
            name:
              data.full_name.trim(),
            email:
              data.email.trim(),
            subject:
              data.subject.trim(),
            message:
              data.message.trim()
          }
        );

        try {

          await sendContactConfirmationEmail(
            env,
            {
              name:
                data.full_name.trim(),
              email:
                data.email.trim()
            }
          );

        } catch (emailError) {

          console.error(
            "Contact confirmation email failed:",
            emailError
          );
        }

        return json(

          {
            success: true,
            message:
              "Thank you for your message! We'll get back to you soon."
          },
          corsHeaders
        );
      }


      /* =====================================================
         DONATION SUBMISSION
      ===================================================== */

      if (
        url.pathname ===
          "/api/donations"
        &&
        request.method === "POST"
      ) {

        const data =
          await request.json();

        const fullName =
          String(data.full_name || "").trim();

        const email =
          String(data.email || "").trim();

        let amountCents;

        if (
          !fullName
          ||
          fullName.length < 2
          ||
          fullName.length > 50
        ) {

          return json(

            {

              success: false,

              error:
                "Full name must be between 2 and 50 characters."

            },

            corsHeaders,

            400
          );
        }

        if (
          !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
            .test(email)
        ) {

          return json(

            {

              success: false,

              error:
                "Please enter a valid email address."

            },

            corsHeaders,

            400
          );
        }

        try {

          amountCents =
            amountToCents(data.amount);

        } catch (amountError) {

          const message =
            amountError.message ||
            "Donation amount is invalid.";

          if (message.includes("greater than zero")) {

            return json(

              {

                success: false,

                error: message

              },

              corsHeaders,

              400
            );
          }

          return json(

            {

              success: false,

              error: message

            },

            corsHeaders,

            400
          );
        }

        const donationId =
          crypto.randomUUID();

        await db.prepare(`
          INSERT INTO donations (

            id,

            full_name,

            email,

            amount_cents,

            created_at

          )

          VALUES (?, ?, ?, ?, ?)
        `)

        .bind(

          donationId,

          fullName,

          email,

          amountCents,

          new Date().toISOString()

        )

        .run();

        return json(

          {

            success: true,

            message:
              "Donation submission recorded successfully."

          },

          corsHeaders,

          201
        );
      }


      /* =====================================================
         DEFAULT API RESPONSE
      ===================================================== */

      return json(

        {

          success: true,

          message:
            "Seeds of Success API"

        },

        corsHeaders
      );


    }

    catch (error) {


      const message =
        error.message || "";


      console.error(
        "Worker error:",
        error
      );


      if (

        message.includes("UNIQUE")

        ||

        message.includes(
          "user_accounts.email"
        )

      ) {

        return json(

          {

            success: false,

            error:
              "An account with this email already exists. Please sign in or use a different email address."

          },

          corsHeaders,

          409
        );
      }


      if (
        message.includes("Message must")
      ) {

        return json(

          {

            success: false,

            error: message

          },

          corsHeaders,

          400
        );
      }


      return json(

        {

          success: false,

          error:
            "Something went wrong. Please try again later."

        },

        corsHeaders,

        500
      );
    }
  }
};
