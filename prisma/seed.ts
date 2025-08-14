import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  // Creează categorii demo
  const categories = [
    'Electronics',
    'Home & Garden',
    'Vehicles',
    'Fashion',
    'Sports',
  ];
  for (const name of categories) {
    await prisma.category.create({ data: { name } });
  }

  // Creează un user demo
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const passwordHash = await bcrypt.hash('password123', 10);
  await prisma.user.create({
    data: {
      name: 'Test User',
      email: 'test@example.com',
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      password: passwordHash,
      role: Role.USER,
    },
  });

  console.log('Seed completed 🌱');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  // eslint-disable-next-line @typescript-eslint/no-misused-promises
  .finally(async () => {
    await prisma.$disconnect();
  });
