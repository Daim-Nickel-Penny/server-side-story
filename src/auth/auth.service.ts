import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    //generate hash

    const hash = await argon.hash(dto.password);

    try {
      // save new user
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: hash,
        },
      });

      delete user.hash;
      // return new user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials Taken');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    //find user by email
    //@Info: find unique helps to find record with any unique field in model
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if no user throw exp
    if (!user) {
      throw new ForbiddenException('Credentials Incorrect');
    }
    //compare password
    const pwMatches = await argon.verify(user.hash, dto.password);
    //if fail password throw err
    if (!pwMatches) {
      throw new ForbiddenException('Password Incorrect');
    }
    //all good send user
    delete user.hash;
    return user;
  }
}
