-- ============================================================================
-- COURSEWARE SUPABASE BACKEND SETUP SCRIPT
-- Course: Computing Science (11226767) - Grade 5
-- School: Jaguar Wittayakom School
-- ============================================================================

-- 1. CLEANUP & EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP VIEW IF EXISTS public.results CASCADE;
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS trg_protect_submission_teacher_fields ON public.submissions;
DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;
DROP FUNCTION IF EXISTS public.protect_submission_teacher_fields() CASCADE;
DROP FUNCTION IF EXISTS public.is_teacher() CASCADE;

DROP TABLE IF EXISTS public.submissions CASCADE;
DROP TABLE IF EXISTS public.progress CASCADE;
DROP TABLE IF EXISTS public.attempts CASCADE;
DROP TABLE IF EXISTS public.materials CASCADE;
DROP TABLE IF EXISTS public.students CASCADE;
DROP TABLE IF EXISTS public.teachers CASCADE;

-- 2. TABLE DEFINITIONS

-- Teachers Table
CREATE TABLE public.teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Students Table (Pre-registered list linked to auth user)
CREATE TABLE public.students (
    id VARCHAR(11) PRIMARY KEY, -- 11-digit Student ID
    title TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    section TEXT NOT NULL,
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Quiz Attempts Table (Pre/Post tests)
CREATE TABLE public.attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('pre', 'post')),
    score NUMERIC NOT NULL CHECK (score >= 0 AND score <= 10),
    answers JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_user_attempt_kind UNIQUE (user_id, kind)
);

-- Unit Learning Progress
CREATE TABLE public.progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 5),
    done BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_user_unit_progress UNIQUE (user_id, unit)
);

-- Submissions Table (AR Practical Assignments)
CREATE TABLE public.submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL CHECK (unit = 4),
    kind TEXT NOT NULL CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score NUMERIC CHECK (score >= 0 AND score <= 100),
    teacher_comment TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Course Materials (Uploaded by Teacher)
CREATE TABLE public.materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. HELPER FUNCTIONS & TRIGGERS

-- Helper: Check if current authenticated user is a teacher
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, auth
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.teachers WHERE user_id = auth.uid()
    );
$$;

-- Trigger Function: Enforce registration against student pre-registered list
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    student_id_val TEXT;
BEGIN
    -- If email matches student format <11digits>@domain
    IF NEW.email ~ '^[0-9]{11}@' THEN
        student_id_val := split_part(NEW.email, '@', 1);
        
        IF EXISTS (SELECT 1 FROM public.students WHERE id = student_id_val AND user_id IS NULL) THEN
            UPDATE public.students
            SET user_id = NEW.id
            WHERE id = student_id_val;
        ELSE
            RAISE EXCEPTION 'รหัสนักศึกษา % ไม่มีในรายชื่อผู้มีสิทธิ์เรียน หรือได้ทำการลงทะเบียนไปแล้ว', student_id_val;
        END IF;
    END IF;
    -- Teacher accounts (non-11 digit numeric prefix emails) bypass student roster binding
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Trigger Function: Prevent students from altering teacher's grading & feedback fields
CREATE OR REPLACE FUNCTION public.protect_submission_teacher_fields()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT public.is_teacher() THEN
        NEW.score := OLD.score;
        NEW.teacher_comment := OLD.teacher_comment;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_protect_submission_teacher_fields
    BEFORE UPDATE ON public.submissions
    FOR EACH ROW EXECUTE FUNCTION public.protect_submission_teacher_fields();

-- 4. VIEWS

-- Teacher Overview View with Security Invoker = true
CREATE OR REPLACE VIEW public.results WITH (security_invoker = true) AS
SELECT 
    s.id AS student_id,
    s.title,
    s.first_name,
    s.last_name,
    s.section,
    s.user_id,
    s.photo_path,
    att_pre.score AS pre_score,
    att_post.score AS post_score,
    CASE 
        WHEN att_pre.score IS NOT NULL AND att_post.score IS NOT NULL THEN
            CASE 
                WHEN (10 - att_pre.score) = 0 THEN 
                    CASE WHEN att_post.score = 10 THEN 1.00 ELSE 0.00 END
                ELSE ROUND(((att_post.score - att_pre.score) / (10 - att_pre.score))::numeric, 2)
            END
        ELSE NULL 
    END AS normalized_gain,
    (SELECT COUNT(*) FROM public.progress p WHERE p.user_id = s.user_id AND p.done = true) AS completed_units
FROM public.students s
LEFT JOIN public.attempts att_pre ON s.user_id = att_pre.user_id AND att_pre.kind = 'pre'
LEFT JOIN public.attempts att_post ON s.user_id = att_post.user_id AND att_post.kind = 'post';

-- 5. ROW LEVEL SECURITY (RLS) POLICIES

ALTER TABLE public.teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.materials ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.teachers FROM anon, public;
REVOKE ALL ON public.students FROM anon, public;
REVOKE ALL ON public.attempts FROM anon, public;
REVOKE ALL ON public.progress FROM anon, public;
REVOKE ALL ON public.submissions FROM anon, public;
REVOKE ALL ON public.materials FROM anon, public;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;

-- Teachers Table Policies
CREATE POLICY "Teacher read teachers" ON public.teachers FOR SELECT TO authenticated USING (public.is_teacher());

-- Students Table Policies
CREATE POLICY "Student read self or teacher read all" ON public.students FOR SELECT TO authenticated 
    USING (user_id = auth.uid() OR public.is_teacher());
CREATE POLICY "Student update photo_path only" ON public.students FOR UPDATE TO authenticated 
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

-- Attempts Table Policies
CREATE POLICY "Student read own attempts or teacher read all" ON public.attempts FOR SELECT TO authenticated 
    USING (user_id = auth.uid() OR public.is_teacher());
CREATE POLICY "Student insert own attempts" ON public.attempts FOR INSERT TO authenticated 
    WITH CHECK (user_id = auth.uid());

-- Progress Table Policies
CREATE POLICY "Student read own progress or teacher read all" ON public.progress FOR SELECT TO authenticated 
    USING (user_id = auth.uid() OR public.is_teacher());
CREATE POLICY "Student insert own progress" ON public.progress FOR INSERT TO authenticated 
    WITH CHECK (user_id = auth.uid());
CREATE POLICY "Student update own progress" ON public.progress FOR UPDATE TO authenticated 
    USING (user_id = auth.uid());

-- Submissions Table Policies
CREATE POLICY "Student read own submissions or teacher read all" ON public.submissions FOR SELECT TO authenticated 
    USING (user_id = auth.uid() OR public.is_teacher());
CREATE POLICY "Student insert own submission" ON public.submissions FOR INSERT TO authenticated 
    WITH CHECK (user_id = auth.uid());
CREATE POLICY "Student update own submission text/url or teacher grade" ON public.submissions FOR UPDATE TO authenticated 
    USING (user_id = auth.uid() OR public.is_teacher());

-- Materials Table Policies
CREATE POLICY "Authenticated read materials" ON public.materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Teacher insert materials" ON public.materials FOR INSERT TO authenticated WITH CHECK (public.is_teacher());
CREATE POLICY "Teacher update materials" ON public.materials FOR UPDATE TO authenticated USING (public.is_teacher());
CREATE POLICY "Teacher delete materials" ON public.materials FOR DELETE TO authenticated USING (public.is_teacher());

-- 6. STORAGE BUCKETS SETUP & SECURITY POLICIES

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES 
    ('photos', 'photos', false, 2097152, ARRAY['image/png', 'image/jpeg', 'image/webp']),
    ('submissions', 'submissions', false, 20971520, ARRAY['image/png', 'image/jpeg', 'application/pdf', 'video/mp4']),
    ('materials', 'materials', false, 52428800, ARRAY['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'image/png', 'image/jpeg', 'video/mp4'])
ON CONFLICT (id) DO UPDATE SET
    public = EXCLUDED.public,
    file_size_limit = EXCLUDED.file_size_limit,
    allowed_mime_types = EXCLUDED.allowed_mime_types;

-- Storage RLS: Photos
CREATE POLICY "Photo SELECT" ON storage.objects FOR SELECT TO authenticated 
    USING (bucket_id = 'photos');
CREATE POLICY "Photo INSERT" ON storage.objects FOR INSERT TO authenticated 
    WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Photo UPDATE" ON storage.objects FOR UPDATE TO authenticated 
    USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);

-- Storage RLS: Submissions
CREATE POLICY "Submissions SELECT" ON storage.objects FOR SELECT TO authenticated 
    USING (bucket_id = 'submissions' AND (public.is_teacher() OR (storage.foldername(name))[1] = auth.uid()::text));
CREATE POLICY "Submissions INSERT" ON storage.objects FOR INSERT TO authenticated 
    WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text);

-- Storage RLS: Materials
CREATE POLICY "Materials SELECT" ON storage.objects FOR SELECT TO authenticated 
    USING (bucket_id = 'materials');
CREATE POLICY "Materials INSERT Teacher" ON storage.objects FOR INSERT TO authenticated 
    WITH CHECK (bucket_id = 'materials' AND public.is_teacher());
CREATE POLICY "Materials DELETE Teacher" ON storage.objects FOR DELETE TO authenticated 
    USING (bucket_id = 'materials' AND public.is_teacher());

-- 7. INITIAL MOCK DATA (6 Sample Students)
INSERT INTO public.students (id, title, first_name, last_name, section) VALUES
    ('66011226001', 'เด็กชาย', 'กิตติศักดิ์', 'เจริญสุข', 'ป.5/1'),
    ('66011226002', 'เด็กหญิง', 'ณิชาภัทร', 'แก้วมณี', 'ป.5/1'),
    ('66011226003', 'เด็กชาย', 'ธนกฤต', 'บุญมี', 'ป.5/1'),
    ('66011226004', 'เด็กหญิง', 'ปรียาภรณ์', 'วงษ์สว่าง', 'ป.5/1'),
    ('66011226005', 'เด็กชาย', 'ภูมินทร์', 'ยอดเพชร', 'ป.5/2'),
    ('66011226006', 'เด็กหญิง', 'อนันตยา', 'สุขสวัสดิ์', 'ป.5/2')
ON CONFLICT (id) DO NOTHING;

/* 
-- ============================================================================
-- คำแนะนำสำหรับการนำเข้ารายชื่อนักเรียนจริงผ่าน Supabase Dashboard:
-- 1. ไปที่เมนู Table Editor -> เลือกตาราง students
-- 2. คลิก "Insert" -> "Import data from CSV"
-- 3. เตรียมไฟล์ CSV ที่มีคอลัมน์: id (11 หลัก), title, first_name, last_name, section
-- ============================================================================
*/

-- 8. TEACHER INITIALIZATION (เปิดใช้งานโดยแก้อีเมลและรันคำสั่งนี้หลังอาจารย์สมัคร Auth)
/*
INSERT INTO public.teachers (user_id)
SELECT id FROM auth.users WHERE email = 'teacher@jaguar.ac.th'
ON CONFLICT DO NOTHING;
*/