@main.route('/room/<hostel>/<block>/<room>')
def room_info(hostel, block, room):
    # Query the database for the user registered to this room
    occupant = User.query.filter_by(
        hostel=hostel,
        block=block,
        room=room
    ).first()
    
    return render_template('room_info.html',
                         hostel=hostel,
                         block=block,
                         room=room,
                         occupant=occupant) 