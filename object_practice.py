import os

class player: 
    def __init__(self, team = None, number = None):

        if (not (team or number)):
            print('null case, nothing provided')
        if (not team):
            print('team not provided')
            self.team = 'default team'


        

    def print_team(self):
        print(self.team)

print('trying both fields')
player1 = player('man city', 5)

print('trying number field')
player1 = player(None, 5)

print('trying team field')
player1 = player('man city')

print('trying null')
player1 = player()
