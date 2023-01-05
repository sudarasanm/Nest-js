import { ForbiddenException, Injectable, RequestTimeoutException } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
        ){}

    async signup(dto:AuthDto){                                              //signup process
        const hash = await argon.hash(dto.password);                        //hashing a password using argon2
        try{
            const user = await this.prisma.user.create({
                data:{
                    email: dto.email,                                       //taking the schema using the dto and prisma
                    hash,
                    
                    
                },
            });
        return this.signToken(user.id, user.email);                         //return the user is valid
        }catch (error){
            if(error instanceof PrismaClientKnownRequestError){             //error for already taken
                if(error.code === 'P2002'){
                    throw new ForbiddenException(
                        'This email is already taken',
                    );
                }
            }
            throw error;
        }
        
    }
    

    async signin(dto:AuthDto){
            const user= 
                await this.prisma.user.findUnique({                         //find the email is validate
                    where: {
                        email:dto.email,
                    },
                });
            if(!user) throw new ForbiddenException(                         //error for not validate users
                'Your email is Incorrect',
            );
            
            const pword = await argon.verify(                               //checking the password is validate
                user.hash,
                dto.password,
            );
            if (!pword) 
                throw new ForbiddenException(                               //error for not validate password
                'Your password is Incorrect',
            );
        return this.signToken(user.id, user.email);                         //sending back the user
    }
    async signToken(
        userId: number, 
        email: string,
        ): Promise<{access_token: string}> {
            const payload = {
                sub: userId,
                email,
            };
            const secret = this.config.get("JWT_SECRET")


            const token = await this.jwt.signAsync(
            payload, 
            {
                expiresIn: '15m',
                secret:'secret',
            });
            return{
                   access_token: token, 
            };
        }
}
