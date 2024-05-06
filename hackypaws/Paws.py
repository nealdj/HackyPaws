import sqlite3 as sql

class Paws:
    def add_profile(name, uploaded_by, description, animal, profile_pic):
        '''
        Adds a single paw profile to the database and links the uploaded profile pic
        '''
        con = sql.connect("hackypaws.db")
        cur = con.cursor()
        add_profile_sql = '''INSERT INTO paws (name, uploaded_by, description, animal, profile_pic)
         VALUES (?, ?, ?, ?, ?);'''
        cur.execute(add_profile_sql, (name, uploaded_by, description, animal, profile_pic))
        con.commit()
        con.close()
        return True

    def get_profile(id):
        '''
        Returns a single Paw Profile
        '''
        con = sql.connect("hackypaws.db")
        cur = con.cursor()
        get_profile_sql = '''SELECT paw_id, uploaded_by, name, description, animal, profile_pic FROM paws
         WHERE paw_id = ?;'''
        cur.execute(get_profile_sql, (id))
        profile = cur.fetchone()
        con.close()
        return {
            "id": profile[0],
            "uploaded_by": profile[1],
            "name": profile[2],
            "description": profile[3],
            "animal": profile[4],
            "profile_pic": profile[5]
        } if profile else False

    def get_all_profile():
        '''
        Returns all paw profiles
        '''
        con = sql.connect("hackypaws.db")
        cur = con.cursor()
        get_all_profile_sql = '''SELECT paw_id, uploaded_by, name, description, animal, profile_pic FROM paws
         ORDER BY paw_id DESC;'''
        cur.execute(get_all_profile_sql)
        paws_result = cur.fetchall()
        con.close()
        return {result[0]: {
                "id": result[0],
                "uploaded_by": result[1],
                "name": result[2],
                "description": result[3],
                "animal": result[4],
                "profile_pic": result[5]
            } for result in paws_result}

    def delete_profile(id):
        '''
        Deletes a single paw profile
        '''
        con = sql.connect("hackypaws.db")
        cur = con.cursor()
        delete_profile_sql = 'DELETE from paws WHERE paw_id = ?;'
        cur.execute(delete_profile_sql, (id))
        con.commit()
        con.close()
        return True

    def allowed_picture(filename):
        '''
        Only allow safe file extensions for paw pictures
        '''
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
        return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS