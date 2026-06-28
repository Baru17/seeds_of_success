const DB_BINDING = "sos_db";

async function hashPassword(password) {
  if (!password) return null;
  const bytes = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function getDb(env) {
  return env[DB_BINDING];
}

function json(data, headers, status = 200) {
  return Response.json(data, { status, headers });
}

function errorResponse(error, headers, status = 500) {
  return json({ success: false, error: error.message }, headers, status);
}

function normalizeStatus(status) {
  const value = String(status || "").toLowerCase();
  if (!["pending", "approved", "rejected"].includes(value)) {
    throw new Error("Invalid status");
  }
  return value;
}

function isValidPhone(phone) {
    return !phone || /^\+[1-9]\d{7,14}$/.test(String(phone).trim());
}

function validateMessage(message) {
  const length = String(message || "").trim().length;
  if (length < 10) throw new Error("Message must be at least 10 characters.");
  if (length > 1000) throw new Error("Message must be 1000 characters or fewer.");
}

function mapStudent(row) {
  const topics = row.topic_names ? row.topic_names.split("||").filter(Boolean) : [];
  const topicScores = row.topic_scores ? row.topic_scores.split("||").map(Number).filter(Number.isFinite) : [];
  const completedTopics = Number(row.completed_topics || 0);
  const totalTopics = Number(row.total_topics || 0);
  const progress = totalTopics ? Math.round((completedTopics / totalTopics) * 100) : 0;
  const averageMarks = topicScores.length
    ? Math.round(topicScores.reduce((sum, score) => sum + score, 0) / topicScores.length)
    : 0;

  return {
    id: row.id,
    full_name: row.full_name,
    grade: row.grade,
    school: row.school,
    status: row.status,
    tutor_id: row.tutor_id,
    tutor_name: row.tutor_name,
    completed_sessions: Number(row.completed_sessions || 0),
    total_topics: totalTopics,
    completed_topics: completedTopics,
    progress,
    average_marks: averageMarks,
    completed_topic_names: topics,
    topic_scores: topicScores,
  };
}

async function getStudents(db) {
  const result = await db.prepare(`
    SELECT
      s.id,
      s.full_name,
      s.grade,
      s.school,
      s.status,
      ua.id AS tutor_id,
      ua.full_name AS tutor_name,
      COUNT(DISTINCT CASE WHEN ts.status = 'completed' THEN ts.id END) AS completed_sessions,
      COUNT(DISTINCT st.id) AS total_topics,
      COUNT(DISTINCT CASE WHEN st.completed_at IS NOT NULL THEN st.id END) AS completed_topics,
      GROUP_CONCAT(CASE WHEN st.completed_at IS NOT NULL THEN st.topic_name END, '||') AS topic_names,
      GROUP_CONCAT(CASE WHEN st.completed_at IS NOT NULL THEN st.score END, '||') AS topic_scores
    FROM students s
    LEFT JOIN student_assignments sa
      ON sa.student_id = s.id AND sa.status = 'active'
    LEFT JOIN user_accounts ua
      ON ua.id = sa.tutor_id
    LEFT JOIN student_topics st
      ON st.student_id = s.id
    LEFT JOIN tutoring_sessions ts
      ON ts.student_id = s.id
    GROUP BY s.id
    ORDER BY s.full_name
  `).all();

  return (result.results || []).map(mapStudent);
}

async function getTutors(db) {
  const result = await db.prepare(`
    SELECT
      ua.id,
      ua.full_name,
      ua.email,
      ua.phone,
      ua.status,
      COUNT(sa.student_id) AS assigned_students
    FROM user_accounts ua
    LEFT JOIN student_assignments sa
      ON sa.tutor_id = ua.id AND sa.status = 'active'
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
    assigned_students: Number(row.assigned_students || 0),
  }));
}

async function getReports(db) {
  const students = await getStudents(db);
  const completedSessions = students.reduce((sum, student) => sum + student.completed_sessions, 0);
  const averageProgress = students.length
    ? Math.round(students.reduce((sum, student) => sum + student.progress, 0) / students.length)
    : 0;
  const scoredStudents = students.filter(student => student.average_marks > 0);
  const averageMarks = scoredStudents.length
    ? Math.round(scoredStudents.reduce((sum, student) => sum + student.average_marks, 0) / scoredStudents.length)
    : 0;
  const activePairs = students.filter(student => student.tutor_id).length;

  return {
    total_completed_sessions: completedSessions,
    average_student_progress: averageProgress,
    average_marks: averageMarks,
    active_tutor_student_pairs: activePairs,
    unassigned_students: students.length - activePairs,
    students,
  };
}

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const db = getDb(env);

    try {
      if (url.pathname === "/api/applications-count" && request.method === "GET") {
        const result = await db
          .prepare("SELECT COUNT(*) as count FROM volunteer_applications")
          .first();

        return json({ success: true, applications: result.count }, corsHeaders);
      }

      if (url.pathname === "/api/application" && request.method === "POST") {
  const data = await request.json();

  if (!isValidPhone(data.phone)) {
    return json({ success: false, error: "Phone number must contain only numbers." }, corsHeaders, 400);
  }

  validateMessage(data.message);

  const existingVolunteer = await db.prepare(`
    SELECT id FROM volunteer_applications
    WHERE email = ?
    LIMIT 1
  `).bind(data.email).first();

  if (existingVolunteer) {
    return json(
      {
        success: false,
        error: "An application with this email already exists. Please sign in or use a different email address."
      },
      corsHeaders,
      409
    );
  }

  await db.prepare(`
    INSERT INTO volunteer_applications (
      id, full_name, email, phone, role, skills, message, password_hash, status, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      crypto.randomUUID(),
      data.full_name,
      data.email,
      data.phone,
      data.role,
      data.skills,
      data.message,
      await hashPassword(data.password || ""),
      "pending",
      new Date().toISOString()
    )
    .run();

  return json({ success: true, message: "Application submitted successfully" }, corsHeaders);
}

      if (url.pathname === "/api/tutor-signup" && request.method === "POST") {
        const data = await request.json();

        if (!isValidPhone(data.phone)) {
          return json({ success: false, error: "Phone number must contain only numbers." }, corsHeaders, 400);
        }

        await db.prepare(`
  INSERT INTO tutor_applications (
    id, full_name, email, phone, skills, availability, password_hash, status, created_at
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`)
.bind(
  crypto.randomUUID(),
  data.full_name,
  data.email,
  data.phone,
  data.skills || "",
  data.availability || "",
  await hashPassword(data.password || ""),
  "pending",
  new Date().toISOString()
)
.run();

return json({ success: true, message: "Tutor application submitted" }, corsHeaders);
      }

      if (url.pathname === "/api/admin/stats" && request.method === "GET") {
        const [tutors, students, pendingApplications, sessions] = await Promise.all([
          db.prepare("SELECT COUNT(*) AS count FROM user_accounts WHERE role = 'tutor'").first(),
          db.prepare("SELECT COUNT(*) AS count FROM students").first(),
          db.prepare("SELECT COUNT(*) AS count FROM volunteer_applications WHERE status = 'pending'").first(),
          db.prepare("SELECT COUNT(*) AS count FROM tutoring_sessions WHERE status = 'completed'").first(),
        ]);

        return json({
          success: true,
          stats: {
            total_tutors: tutors.count || 0,
            total_students: students.count || 0,
            pending_applications: pendingApplications.count || 0,
            completed_sessions: sessions.count || 0,
          },
        }, corsHeaders);
      }

      if (url.pathname === "/api/admin/volunteer-applications" && request.method === "GET") {
        const result = await db.prepare(`
          SELECT id, full_name, email, phone, role, skills, message, status, created_at, reviewed_at
          FROM volunteer_applications
          ORDER BY
            CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
            created_at DESC
        `).all();

        return json({ success: true, applications: result.results || [] }, corsHeaders);
      }

      const volunteerStatusMatch = url.pathname.match(/^\/api\/admin\/volunteer-applications\/([^/]+)\/status$/);
      if (volunteerStatusMatch && request.method === "PATCH") {
        const applicationId = decodeURIComponent(volunteerStatusMatch[1]);
        const { status } = await request.json();
        const normalizedStatus = normalizeStatus(status);
        const reviewedAt = new Date().toISOString();

        await db.prepare(`
          UPDATE volunteer_applications
          SET status = ?, reviewed_at = ?
          WHERE id = ?
        `).bind(normalizedStatus, reviewedAt, applicationId).run();

        const application = await db.prepare(`
          SELECT id, full_name, email, phone, role, skills, message, status, created_at, reviewed_at
          FROM volunteer_applications
          WHERE id = ?
        `).bind(applicationId).first();

        if (!application) return json({ success: false, error: "Application not found" }, corsHeaders, 404);

        if (normalizedStatus === "approved") {
          const existingUser = await db.prepare("SELECT id FROM user_accounts WHERE email = ?").bind(application.email).first();
          let userId = existingUser?.id;
          if (!userId) {
            userId = crypto.randomUUID();
            await db.prepare(`
              INSERT INTO user_accounts (
                id, full_name, email, phone, role, status, notification_message, created_at, updated_at
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
              userId,
              application.full_name,
              application.email,
              application.phone,
              "volunteer",
              "active",
              "Your volunteer application has been approved.",
              reviewedAt,
              reviewedAt
            ).run();
          }

          await db.prepare(`
            INSERT INTO notifications (
              id, recipient_user_id, recipient_email, message, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(
            crypto.randomUUID(),
            userId,
            application.email,
            "Your volunteer application has been approved. Thank you for joining Seeds of Success.",
            "queued",
            reviewedAt
          ).run();
        }

        return json({ success: true, application }, corsHeaders);
      }

      if (url.pathname === "/api/admin/tutors" && request.method === "GET") {
        return json({ success: true, tutors: await getTutors(db) }, corsHeaders);
      }

      if (url.pathname === "/api/admin/students" && request.method === "GET") {
        return json({ success: true, students: await getStudents(db) }, corsHeaders);
      }

      if (url.pathname === "/api/admin/assign-tutor" && request.method === "POST") {
        const { student_id, tutor_id, assigned_by_admin_id } = await request.json();
        if (!student_id) return json({ success: false, error: "student_id is required" }, corsHeaders, 400);

        const now = new Date().toISOString();
        await db.prepare(`
          UPDATE student_assignments
          SET status = 'reassigned', updated_at = ?
          WHERE student_id = ? AND status = 'active'
        `).bind(now, student_id).run();

        if (tutor_id) {
          await db.prepare(`
            INSERT INTO student_assignments (
              id, student_id, tutor_id, assigned_by_admin_id, status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).bind(
            crypto.randomUUID(),
            student_id,
            tutor_id,
            assigned_by_admin_id || null,
            "active",
            now,
            now
          ).run();
        }

        return json({ success: true, students: await getStudents(db), tutors: await getTutors(db) }, corsHeaders);
      }

      if (url.pathname === "/api/admin/reports" && request.method === "GET") {
        return json({ success: true, reports: await getReports(db) }, corsHeaders);
      }

      if (url.pathname === "/api/admin/volunteer-tasks" && request.method === "POST") {
        const data = await request.json();
        if (!data.volunteer_id || !data.task_title) {
          return json({ success: false, error: "volunteer_id and task_title are required" }, corsHeaders, 400);
        }

        const now = new Date().toISOString();
        const taskId = crypto.randomUUID();
        await db.prepare(`
          INSERT INTO volunteer_tasks (
            id, volunteer_id, assigned_by_admin_id, task_title, task_notes, due_at, status, created_at, updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          taskId,
          data.volunteer_id,
          data.assigned_by_admin_id || null,
          data.task_title,
          data.task_notes || null,
          data.due_at || null,
          "open",
          now,
          now
        ).run();

        const task = await db.prepare(`
          SELECT vt.id, vt.volunteer_id, ua.full_name AS volunteer_name, vt.task_title, vt.task_notes, vt.due_at, vt.status, vt.created_at
          FROM volunteer_tasks vt
          JOIN user_accounts ua ON ua.id = vt.volunteer_id
          WHERE vt.id = ?
        `).bind(taskId).first();

        return json({ success: true, task }, corsHeaders, 201);
      }

      return json({ success: true, message: "Seeds of Success API" }, corsHeaders);
    } catch (error) {
  const message = error.message || "";

  if (message.includes("UNIQUE") || message.includes("user_accounts.email")) {
    return json(
      {
        success: false,
        error: "An account with this email already exists. Please sign in or use a different email address."
      },
      corsHeaders,
      409
    );
  }

  if (message.includes("Message must")) {
    return json({ success: false, error: message }, corsHeaders, 400);
  }

  return json(
    {
      success: false,
      error: "Something went wrong. Please try again later."
    },
    corsHeaders,
    500
  );
}
  }
};
